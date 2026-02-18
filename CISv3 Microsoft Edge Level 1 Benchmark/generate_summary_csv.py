"""
Generate a summary CSV for CIS Microsoft Edge Level 1 (CISv3) policies.
Reads from:
  - CISv3 Microsoft Edge Level 1 Benchmark (root .json files)

Columns:
  A: Name (from "name" field)
  B: Description (from "description" field, cleaned)
  C: Recommended Setting (extracted from description → payload inference → N/A)
  D: Complexity (Simple / Moderate / Complex)
  E: SMB Justification (if not using recommended)
"""

import json
import csv
import os
import re
import glob

SAMPLE_MODE = False   # Set True to process first 20 policies only
SAMPLE_COUNT = 20

# ── Complexity keyword maps ────────────────────────────────────────────────────

# Complex: policies with significant interplay, auth stacks, or attack surface.
COMPLEX_KEYWORDS = [
    "asr", "attack surface reduction",
    "ntlm", "ntlmssp", "lan manager",
    "pku2u", "wmi", "psexec",
    "lsa protected", "lsa process",
    "kerberos", "sam account",
    "rpc", "smb v1",
    "redirection guard",
    "system guard", "boot-start driver",
    "config refresh",
    # Edge-specific complex areas
    "site isolation",
    "legacy extension point",
    "audio sandbox",
    "remote debugging",
    "hsts",
    "webrtc",
    "insecure content",
    "experimentation and configuration",
]

# Moderate: policies that need validation but are well-understood.
MODERATE_KEYWORDS = [
    "audit", "event log", "log file", "log max", "specify the maximum",
    "uac", "user account control", "elevation prompt",
    "network access", "network security",
    "device password", "device lock",
    "winrm",
    "solicited remote", "offer remote assistance",
    "smartscreen",
    "firewall",
    "credential manager",
    "smb",
    "ipsec",
    # Edge-specific moderate areas
    "autofill",
    "password manager",
    "saving passwords",
    "import",
    "synchronization",
    "sync",
    "inprivate",
    "browsing data",
    "browsing history",
    "browser history",
    "download",
    "extension",
    "cast",
    "payment",
    "autofill",
    "update policy",
    "component update",
    "browser network time",
    "dns interception",
    "navigation errors",
    "insecure forms",
    "command-line flags",
    "security warnings",
    "profile creation",
    "linked account",
    "clear browsing",
    "clear cached",
    "clear history",
    "ephemeral profiles",
    "internet explorer",
    "ie mode",
    "share experience",
    "startup boost",
    "background apps",
]


def assess_complexity(name: str, setting_count: int) -> str:
    """Return Simple / Moderate / Complex based on heuristics."""
    name_lower = name.lower()

    if any(kw in name_lower for kw in COMPLEX_KEYWORDS):
        return "Complex"
    if setting_count > 3:
        return "Complex"
    if any(kw in name_lower for kw in MODERATE_KEYWORDS):
        return "Moderate"
    if setting_count > 1:
        return "Moderate"
    return "Simple"


# ── SMB justification lookup ──────────────────────────────────────────────────

def smb_justification(name: str, recommended: str, complexity: str) -> str:
    """Return a pre-filled SMB-context justification for not using the recommended setting."""
    name_lower = name.lower()

    # SmartScreen
    if "smartscreen" in name_lower:
        return (
            "Microsoft Defender SmartScreen is a key browser-level phishing and malware protection layer. "
            "Only skip if a third-party DNS filter or web proxy already provides equivalent real-time URL reputation checking."
        )

    # Download restrictions
    if "download restriction" in name_lower:
        return (
            "Blocking dangerous downloads reduces malware risk significantly. "
            "The configured value (Block malicious downloads) is the recommended CIS balance; "
            "only relax if a specific LOB workflow requires downloading file types flagged by Safe Browsing."
        )

    # Prevent bypassing SmartScreen
    if "prevent bypassing" in name_lower:
        return (
            "Allowing users to bypass SmartScreen warnings defeats the protection entirely. "
            "There is no valid SMB business reason to enable bypass; keep at recommended unless an explicit exception process exists."
        )

    # Site isolation
    if "site isolation" in name_lower:
        return (
            "Site isolation is a defence-in-depth control against cross-site data leakage attacks (Spectre/Meltdown mitigations). "
            "Memory overhead is the only trade-off; only disable on severely RAM-constrained devices."
        )

    # Legacy extension point blocking
    if "legacy extension point" in name_lower:
        return (
            "Blocking legacy browser extension injection points prevents DLL-injection attacks via older browser hooks. "
            "Only disable if a specific LOB tool explicitly requires legacy extension point access — contact the vendor for a modern alternative."
        )

    # Audio sandbox
    if "audio sandbox" in name_lower:
        return (
            "The audio sandbox isolates the audio process to limit the impact of audio codec exploits. "
            "Disabling it should only be considered if a specific audio driver incompatibility is documented."
        )

    # Remote debugging
    if "remote debugging" in name_lower:
        return (
            "Allowing remote debugging creates a significant attack surface — any process can inspect page content and credentials. "
            "This should always be disabled in managed SMB endpoints; there is no valid production use case for enabling it."
        )

    # Autofill — addresses / payment
    if "autofill" in name_lower:
        if "payment" in name_lower or "payment instructions" in name_lower:
            return (
                "Disabling payment autofill prevents the browser from storing payment card data, reducing credential/financial data exposure. "
                "Some users may find this inconvenient; communicate the change and note that password manager integrations are unaffected."
            )
        return (
            "Disabling address autofill prevents the browser from storing personal address data locally. "
            "Low operational impact; users can still manually enter addresses. Acceptable trade-off for data privacy."
        )

    # Password saving
    if "saving passwords" in name_lower or "save" in name_lower and "password" in name_lower:
        return (
            "Disabling the built-in password manager forces users to a centrally managed password manager (e.g., 1Password, Bitwarden). "
            "Communicate the policy change and ensure an approved alternative is deployed before enforcing."
        )

    # Importing data / browser settings
    if "import" in name_lower:
        if "data from other browsers" in name_lower:
            return (
                "Disabling auto-import on each launch prevents personal browser data leaking into the managed Edge profile. "
                "Users who migrate from another browser may notice this; provide guidance on first-run import only."
            )
        return (
            "Blocking import of saved passwords, autofill data, or settings from other browsers prevents unmanaged credential bleed-over. "
            "Low operational impact for users who are already on managed Edge profiles."
        )

    # Sync / synchronization
    if "synchronization" in name_lower or "sync" in name_lower:
        return (
            "Disabling Microsoft sync prevents browser data (history, passwords, favourites) from leaving the managed device. "
            "Essential for data governance in M365-managed SMBs. Only deviate if cross-device sync is a documented business requirement."
        )

    # Browsing data / history clearing
    if "clear browsing" in name_lower or "clear cached" in name_lower or "clear history" in name_lower or "disable saving browser history" in name_lower:
        return (
            "Enforcing browsing data clearing on exit reduces residual data exposure on shared or unattended devices. "
            "Users on dedicated personal devices may find this disruptive; balance privacy requirements with usability."
        )

    # InPrivate mode
    if "inprivate" in name_lower:
        return (
            "Disabling InPrivate mode prevents users from circumventing browsing history and web filter policies. "
            "Only enable if a specific workflow requires untracked browsing and compensating controls exist."
        )

    # Extensions / external extensions
    if "extension" in name_lower:
        return (
            "Blocking external or unmanaged extensions prevents malicious browser add-ons. "
            "Use the Intune app deployment or Edge extension allowlist to deploy approved extensions rather than enabling open install."
        )

    # Payment methods query
    if "payment methods" in name_lower:
        return (
            "Preventing websites from querying available payment methods reduces fingerprinting and payment data exposure. "
            "Negligible impact for most SMB users; only relevant if a web app relies on the Payment Request API."
        )

    # Google Cast
    if "cast" in name_lower:
        return (
            "Disabling Google Cast removes the ability to cast browser content to Chromecast/Cast-capable devices. "
            "Only enable if users legitimately use Chromecast for presentations; low security risk either way."
        )

    # User feedback / in-app support
    if "user feedback" in name_lower or "in-app support" in name_lower:
        return (
            "Disabling built-in feedback and support channels prevents telemetry and user data from being sent to Microsoft/Google via these paths. "
            "IT support should provide an alternative channel; users may initially miss the quick feedback button."
        )

    # Intrusive ads
    if "intrusive ads" in name_lower or "ads setting" in name_lower:
        return (
            "Blocking intrusive ads on sites with poor ad experiences is low-risk and improves security posture. "
            "Only deviate if an internal site is incorrectly flagged — add it to the ads exception list rather than disabling globally."
        )

    # Cross-origin HTTP auth prompts
    if "cross-origin" in name_lower and "auth" in name_lower:
        return (
            "Blocking cross-origin HTTP authentication prompts prevents credential phishing via embedded cross-origin resources. "
            "Rarely needed in modern SMB web apps; only enable if a specific intranet application requires it."
        )

    # Basic authentication for HTTP
    if "basic authentication" in name_lower and "http" in name_lower:
        return (
            "Disabling Basic auth over plain HTTP prevents credentials being sent in cleartext. "
            "No valid reason to enable this in 2025; if an internal app requires it, migrate the app to HTTPS first."
        )

    # Allow queries to browser network time service
    if "browser network time" in name_lower:
        return (
            "Allowing Edge to query a browser network time service improves certificate validation accuracy. "
            "Low-risk to enable; only block if strict egress filtering prevents outbound time service queries."
        )

    # DNS interception checks
    if "dns interception" in name_lower:
        return (
            "DNS interception checks help detect captive portals and network interception. "
            "Low-risk to enable; only disable if a network appliance generates false positive interception detections."
        )

    # Navigation error resolution (web service)
    if "navigation errors" in name_lower:
        return (
            "Disabling the web service for navigation error resolution prevents page-not-found queries being sent to Google/Microsoft. "
            "Privacy control; negligible UX impact since the feature primarily provides suggestions for mistyped URLs."
        )

    # Insecure content exceptions
    if "insecure content" in name_lower:
        return (
            "Preventing users from allowing insecure (mixed HTTP/HTTPS) content maintains TLS integrity on HTTPS pages. "
            "Only relax for internal sites that cannot be updated to full HTTPS — add per-site exceptions rather than a global allow."
        )

    # Insecure forms warnings
    if "insecure forms" in name_lower:
        return (
            "Showing warnings for forms submitted over HTTP is a low-friction security signal. "
            "Only disable if internal legacy forms generate false-positive warnings and cannot be migrated to HTTPS."
        )

    # Command-line flags / security warnings
    if "command-line flags" in name_lower or "security warnings" in name_lower and "command" in name_lower:
        return (
            "Suppressing security warnings for unsafe command-line flags makes it easier to exploit Edge via custom flags. "
            "No valid operational reason to disable this in a managed SMB environment."
        )

    # Profile creation
    if "profile creation" in name_lower:
        return (
            "Blocking self-service profile creation prevents users from adding personal Microsoft accounts to the managed Edge browser. "
            "Maintain corporate profile integrity; only enable if a specific multi-identity workflow is approved."
        )

    # Ephemeral profiles
    if "ephemeral profiles" in name_lower:
        return (
            "Ephemeral profiles wipe all browser data on close, which can conflict with Intune-managed settings persistence. "
            "Use only for kiosk/shared-device scenarios; avoid on standard user endpoints."
        )

    # Linked account feature
    if "linked account" in name_lower:
        return (
            "Disabling the linked account feature prevents personal Microsoft account linking in the work Edge profile. "
            "Keeps corporate and personal identities separate; no business justification to enable in a managed SMB."
        )

    # Startup boost
    if "startup boost" in name_lower:
        return (
            "Startup boost keeps Edge processes running in the background after closing, reducing load time. "
            "Security-neutral; only disable if background processes are a concern on low-spec devices."
        )

    # Background apps
    if "background apps" in name_lower:
        return (
            "Allowing apps to run after Edge closes keeps progressive web apps (PWAs) active. "
            "Low risk; disable if users report unexpected resource usage from background Edge processes."
        )

    # Tab organisation / AI suggestions
    if "tab organization" in name_lower:
        return (
            "Disabling AI-powered tab organization suggestions prevents page content from being sent to Microsoft AI services. "
            "Privacy control; no business functionality is lost — users can still organise tabs manually."
        )

    # Search bar
    if "search bar" in name_lower:
        return (
            "Disabling the Edge sidebar search bar reduces unnecessary UI surface and avoids ambient data collection. "
            "Low operational impact; users can still search via the address bar."
        )

    # Bing / Copilot entry points
    if "bing" in name_lower or "copilot" in name_lower or "discover" in name_lower:
        return (
            "Disabling Bing Chat / Copilot entry points in Edge prevents users from sharing page content with AI services without explicit consent. "
            "Apply in environments with data classification requirements; communicate the change to users."
        )

    # Compose / writing on the web
    if "compose" in name_lower or "dall-e" in name_lower:
        return (
            "Disabling Edge AI writing and image generation features prevents page content from being submitted to Microsoft AI services. "
            "Appropriate for environments with data handling obligations; no core productivity feature is lost."
        )

    # Shopping / rewards / wallet / crypto
    if "shopping" in name_lower or "rewards" in name_lower or "wallet" in name_lower or "crypto" in name_lower or "donation" in name_lower:
        return (
            "Disabling Edge consumer features (Shopping, Rewards, Wallet, CryptoWallet) removes non-business browser functions. "
            "No business impact; reduces distraction and potential data sharing with Microsoft consumer services."
        )

    # Follow service / Edge 3P SERP / Guided Switch / Sidebar
    if "follow service" in name_lower or "3p serp" in name_lower or "guided switch" in name_lower or "standalone sidebar" in name_lower:
        return (
            "Disabling Edge consumer engagement features (Follow, Sidebar, Guided Switch) reduces data telemetry and non-work distractions. "
            "No business functionality is impacted; these are consumer-oriented browser features."
        )

    # Reload in IE mode button
    if "internet explorer mode" in name_lower or "ie mode" in name_lower or "reload in internet explorer" in name_lower:
        return (
            "Hiding the IE mode reload button discourages reliance on legacy IE rendering. "
            "Only enable if specific internal web apps require IE mode and are awaiting modernisation."
        )

    # Suppress unsupported OS warning
    if "unsupported os" in name_lower:
        return (
            "Suppressing the unsupported OS warning hides a security signal — it should be shown. "
            "The recommended setting is Disabled (do not suppress warnings). "
            "Only deviate if OS upgrade cannot be expedited and the warning causes user confusion."
        )

    # Update policy / component updates
    if "update policy" in name_lower or "component update" in name_lower or "set the time period for update" in name_lower:
        return (
            "Edge update policies should align with the organisation's patch management cadence. "
            "Ensure updates are not blocked for extended periods; use Intune Update Rings or equivalent to manage timing."
        )

    # Delete old browser data on migration
    if "delete old browser data" in name_lower:
        return (
            "Deleting old browser data during migration removes stale personal data from managed profiles. "
            "Low-risk; only skip if users need to retain legacy browser data during a phased migration."
        )

    # HSTS bypass
    if "hsts" in name_lower:
        return (
            "The HSTS bypass name list should be empty in production environments. "
            "Adding hostnames bypasses strict transport security and re-enables downgrade attacks on those hosts. "
            "Only populate for specific internal hosts that cannot serve valid TLS and have no remediation path."
        )

    # WebRTC IP exposure
    if "webrtc" in name_lower:
        return (
            "Managing WebRTC local IP address exposure prevents internal network topology leakage through browser-based video calls. "
            "The recommended DisableNonProxiedUdp or HideMyLocalIp setting reduces risk with minimal Teams/Zoom impact."
        )

    # Upload files from mobile
    if "upload" in name_lower and "mobile" in name_lower:
        return (
            "Disabling mobile file upload integration removes a consumer cross-device feature rarely needed in managed SMBs. "
            "Low operational impact; enterprise file sharing should use approved cloud storage (SharePoint, OneDrive)."
        )

    # Feature flags override
    if "feature flags" in name_lower:
        return (
            "Preventing users from overriding feature flags ensures Edge remains in its managed configuration state. "
            "Enabling user flag overrides can introduce untested features and bypass IT-configured settings."
        )

    # Share experience
    if "share experience" in name_lower:
        return (
            "Configuring or disabling the Edge share experience reduces unnecessary data sharing via consumer share targets. "
            "Set to ShareAllowed with approved targets only, or disable if no sharing workflow is needed."
        )

    # Related matches in Find on Page
    if "related matches" in name_lower or "find on page" in name_lower:
        return (
            "Disabling AI-powered 'Related Matches' in Find on Page prevents page content from being sent to Microsoft for fuzzy search. "
            "Privacy control; basic Find (Ctrl+F) functionality is unaffected."
        )

    # Website typo protection
    if "typo protection" in name_lower:
        return (
            "Enabling Edge website typo protection warns users about mistyped URLs that may lead to lookalike phishing sites. "
            "Low-friction security feature; only disable if it generates false positives for internal hostnames."
        )

    # Hide first-run experience
    if "first-run" in name_lower or "first run" in name_lower or "splash screen" in name_lower:
        return (
            "Hiding the Edge first-run splash screen reduces user prompts to add personal accounts or import personal data. "
            "Recommended for managed deployments; no functionality is lost."
        )

    # Globally scoped HTTP auth cache
    if "globally scoped" in name_lower and "auth" in name_lower:
        return (
            "Disabling globally scoped HTTP auth cache prevents authentication credentials for one site from being reused by other pages. "
            "Reduces credential reuse risk with minimal impact on modern web apps that use token-based auth."
        )

    # Disk cache size
    if "disk cache size" in name_lower:
        return (
            "Setting a maximum disk cache size limits Edge disk usage on constrained devices. "
            "The CIS recommended value (250 MB) is a reasonable cap; adjust upward for power users with high web app usage."
        )

    # Managed extensions Enterprise Hardware Platform API
    if "enterprise hardware platform" in name_lower:
        return (
            "Allowing managed extensions to use the Enterprise Hardware Platform API should be scoped only to verified enterprise extensions. "
            "Limit to allowlisted extensions only; do not enable globally."
        )

    # Edge E-Tree / 3P SERP / misc telemetry flags
    if "e-tree" in name_lower or "etree" in name_lower:
        return (
            "Disabling Edge E-Tree (environmental/charity donation features) removes a consumer engagement feature from the managed browser. "
            "No business impact."
        )

    # Default fallback — name-aware
    prefix_pattern = re.compile(r"^cisv3\s*-\s*edge\s*-\s*l1\s*-\s*", re.IGNORECASE)
    name_words = prefix_pattern.sub("", name_lower).strip()

    if complexity == "Simple":
        return (
            f"'{name_words}' is a low-complexity, single-value setting with minimal operational impact. "
            "Apply the recommended state; deviation requires a specific documented business or technical exception."
        )
    if complexity == "Moderate":
        return (
            f"'{name_words}' has moderate implementation risk. "
            "Validate against existing browser workflows and extensions; pilot on a test group before broad rollout."
        )
    return (
        f"'{name_words}' is a complex Edge policy with potential dependencies on other browser features or web apps. "
        "Engage with the client to map dependencies before enforcing. "
        "Use Edge policy reporting to validate impact before enforcement."
    )


# ── Description extraction helpers ───────────────────────────────────────────

# Maps common settingDefinitionId value token suffixes to human-readable labels.
_PAYLOAD_VALUE_MAP = {
    "_block": "Block",
    "_audit": "Audit Mode",
    "_disabled": "Disabled",
    "_enabled": "Enabled",
    "_true": "Enabled (True)",
    "_false": "Disabled (False)",
    "_0": "Disabled / Off",
    "_1": "Enabled / On",
    "_2": "Option 2",
    "_3": "Option 3",
    "_4": "Option 4",
    "_5": "Option 5",
    "_6": "Option 6",
    "_warn": "Warn",
    "_off": "Off",
    "_on": "On",
}


def _infer_from_payload(data: dict) -> str:
    """
    Walk the first settingInstance value field and map to a human label.
    Returns a tagged string or None if unmappable.
    """
    try:
        settings = data.get("settings", [])
        if not settings:
            return None
        instance = settings[0].get("settingInstance", {})

        # choiceSettingValue → value token
        choice = instance.get("choiceSettingValue", {})
        if choice:
            raw_value = choice.get("value", "")
        else:
            # groupSettingCollectionValue → first child choiceSettingValue
            groups = instance.get("groupSettingCollectionValue", [])
            if groups:
                children = groups[0].get("children", [])
                if children:
                    raw_value = children[0].get("choiceSettingValue", {}).get("value", "")
                else:
                    return None
            else:
                # simpleSettingValue → integer/string
                simple = instance.get("simpleSettingValue", {})
                if simple:
                    v = simple.get("value")
                    if v is not None:
                        return f"{v} (configured value)"
                return None

        if not raw_value:
            return None

        raw_lower = raw_value.lower()
        # Longest suffix match wins
        for suffix, label in sorted(_PAYLOAD_VALUE_MAP.items(), key=lambda x: -len(x[0])):
            if raw_lower.endswith(suffix) or suffix in raw_lower:
                return f"{label} (inferred from payload)"

        # Last resort: bare trailing token
        token = raw_value.rsplit("_", 1)[-1] if "_" in raw_value else raw_value
        return f"{token} (inferred from payload)"

    except Exception:
        return None


def extract_recommended(description: str, data: dict = None, name: str = "") -> str:
    """
    Extract 'The recommended state for this setting is: X' sentence.
    Falls back to payload inference, then N/A.
    """
    match = re.search(
        r"The recommended state for this setting is[:\s]+(.+?)(?:\.|$)",
        description,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        value = match.group(1).strip()
        value = re.sub(r"\s+", " ", value).strip(" .")
        return value

    if data is not None:
        inferred = _infer_from_payload(data)
        if inferred:
            return inferred

    return "N/A"


def clean_description(description: str) -> str:
    """Clean description for CSV — collapse whitespace, strip trailing newlines."""
    return re.sub(r"\s+", " ", description).strip()


# ── File parsing ──────────────────────────────────────────────────────────────

def parse_policy_file(filepath: str) -> dict | None:
    """Parse a single policy JSON file and return a dict of fields."""
    try:
        with open(filepath, encoding="utf-16") as f:
            data = json.load(f)
    except Exception:
        try:
            with open(filepath, encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  SKIP (parse error): {os.path.basename(filepath)} — {e}")
            return None

    name = data.get("name", "").strip()
    raw_description = data.get("description", "").strip()
    setting_count = data.get("settingCount", 1)

    description = clean_description(raw_description)
    recommended = extract_recommended(raw_description, data, name)
    complexity = assess_complexity(name, setting_count)
    justification = smb_justification(name, recommended, complexity)

    return {
        "Name": name,
        "Description": description,
        "Recommended Setting": recommended,
        "Complexity": complexity,
        "SMB Justification (if not using recommended)": justification,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "Summary CSV")
os.makedirs(OUTPUT_DIR, exist_ok=True)

all_files = sorted(glob.glob(os.path.join(BASE_DIR, "*.json")))
print(f"Total JSON files found: {len(all_files)}")

rows = []
for fp in all_files:
    result = parse_policy_file(fp)
    if result:
        rows.append(result)
    if SAMPLE_MODE and len(rows) >= SAMPLE_COUNT:
        break

print(f"Rows parsed: {len(rows)}")

output_filename = "CIS_EDGE_L1_Policy_Summary_SAMPLE.csv" if SAMPLE_MODE else "CIS_EDGE_L1_Policy_Summary_FULL.csv"
output_path = os.path.join(OUTPUT_DIR, output_filename)

fieldnames = [
    "Name",
    "Description",
    "Recommended Setting",
    "Complexity",
    "SMB Justification (if not using recommended)",
]

with open(output_path, "w", newline="", encoding="utf-8-sig") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"\nCSV written to: {output_path}")
print(f"Rows written: {len(rows)}")
