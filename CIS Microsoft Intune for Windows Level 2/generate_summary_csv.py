"""
Generate a summary CSV for CIS Intune for Windows Level 2 policies.
Reads from:
  - CIS Microsoft Intune for Windows Level 2 (root .json files only)

There is no Unmerged Policies or Merged Policies subfolder in Level 2.

Columns:
  A: name (from "name" field)
  B: description (from "description" field, cleaned)
  C: Recommended setting (extracted trailing sentence from description)
  D: Complexity (Simple / Moderate / Complex)
  E: SMB justification for not using recommended setting
"""

import json
import csv
import os
import re
import glob

# ── Complexity assessment keyword maps ────────────────────────────────────────

# Complex: policies with significant interplay with other systems, auth stacks,
# or attack surface that require careful testing before enforcement.
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
    "powershell",          # Script block logging / transcription
    "mss",                 # MSS legacy TCP settings
    "tcp",                 # TCP-level settings
    "mapper io", "lltdio", "rspndr",   # Link-layer topology / responder drivers
]

# Moderate: policies that need validation but are well-understood and lower-risk.
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
    "remote desktop", "rdp",       # RDP session / clipboard settings
    "remote shell",                # Allow Remote Shell Access
    "onedrive", "one drive",       # OneDrive sync
    "store",                       # App Store / Store apps
    "watson",                      # Watson/MSDT telemetry
    "msdt",
    "kms",                         # KMS activation validation
    "enterprise auth proxy",       # Enterprise Auth Proxy
    "connect now",                 # Windows Connect Now / wireless
    "plug and play",               # PnP redirection
    "print", "printer",            # Printer driver install / printing over HTTP
    "ink workspace",               # Windows Ink Workspace
    "spotlight",                   # Windows Spotlight
]


def assess_complexity(name: str, description: str, setting_count: int) -> str:
    """Return Simple / Moderate / Complex based on heuristics."""
    # Match against name only (more precise than combined name+description,
    # which causes false positives from descriptive prose).
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

    # ── PowerShell logging / transcription ───────────────────────────────────
    if "powershell" in name_lower:
        if "transcription" in name_lower:
            return (
                "PowerShell Transcription writes all session input/output to disk, which can generate "
                "large log files on constrained endpoints and may capture sensitive credential strings. "
                "Strongly recommended for incident response; ensure log directory is protected and rotated."
            )
        if "script block" in name_lower or "block logging" in name_lower:
            return (
                "Script Block Logging is critical for detecting malicious PowerShell and is a low-disruption setting. "
                "Enable on all managed endpoints. Only skip if a SIEM or EDR already captures equivalent telemetry."
            )
        return (
            "PowerShell logging settings are strongly recommended for security visibility. "
            "No legitimate operational reason exists to skip them on managed SMB endpoints."
        )

    # ── MSS TCP legacy settings ───────────────────────────────────────────────
    if "mss" in name_lower or "tcp" in name_lower or "keepalive" in name_lower:
        if "disablesavepassword" in name_lower or "save password" in name_lower or "dial" in name_lower:
            return (
                "Dial-up password saving is a legacy concern. Modern SMBs do not use dial-up; "
                "apply the recommended state. Deviation is not justified in cloud-managed environments."
            )
        if "keepalive" in name_lower or "keep-alive" in name_lower:
            return (
                "TCP keep-alive tuning is a low-risk network hardening measure. "
                "Only deviate if specific applications rely on non-standard keep-alive intervals."
            )
        if "retransmission" in name_lower:
            return (
                "Limiting TCP retransmissions reduces exposure to slow-loris-style DoS. "
                "Test on latency-sensitive links before broad deployment; 3 retransmissions is the CIS-recommended value."
            )
        if "routerdiscovery" in name_lower or "irdp" in name_lower or "perform router" in name_lower:
            return (
                "IRDP router discovery can expose endpoints to rogue gateway attacks. "
                "Disabling is low-risk for SMBs; only enable if IRDP is explicitly required by a network device."
            )
        return (
            "MSS registry settings are low-disruption network hardening tweaks. "
            "Apply the recommended state; deviation is rarely justified in managed SMB environments."
        )

    # ── Remote Desktop / RDP ─────────────────────────────────────────────────
    if "remote desktop" in name_lower or "rdp" in name_lower or "remote shell" in name_lower:
        if "clipboard" in name_lower:
            return (
                "Restricting server-to-client clipboard is a strong data-loss-prevention control. "
                "May frustrate users who copy/paste between local and remote desktop sessions. "
                "Evaluate whether RDS/VDI use cases justify enabling bidirectional clipboard."
            )
        if "time limit" in name_lower or "disconnected" in name_lower or "idle" in name_lower:
            return (
                "RDP session time limits prevent abandoned sessions from accumulating. "
                "Tune to match business workflows; overly short limits may disrupt long-running tasks."
            )
        if "allow users to connect" in name_lower:
            return (
                "Enabling Remote Desktop access is a significant attack surface expansion. "
                "For SMBs, RMM tools (e.g., N-sight, Datto RMM) replace direct RDP. "
                "Disable unless RDP is explicitly required and protected by MFA/NLA."
            )
        if "remote shell" in name_lower:
            return (
                "Remote Shell (WinRM shell) access provides command-line remote execution. "
                "Disabling is strongly recommended; use RMM or Azure Arc for remote management instead."
            )
        if "com port" in name_lower or "lpt port" in name_lower or "plug and play" in name_lower:
            return (
                "Port and device redirection in RDP sessions can expose endpoint peripherals to remote sessions. "
                "Blocking is recommended; only enable if specific line-of-business RDS workflows require device redirection."
            )
        return (
            "Remote Desktop settings affect a high-value attack vector. "
            "Apply CIS-recommended restrictions; document any exceptions with compensating controls."
        )

    # ── WinRM service management ─────────────────────────────────────────────
    if "winrm" in name_lower or ("remote server management" in name_lower and "winrm" in name_lower):
        return (
            "Disabling unauthenticated/unencrypted WinRM is critical for lateral movement prevention. "
            "Some RMM tools depend on WinRM; migrate to HTTPS/Kerberos-authenticated WinRM or use your RMM's agent channel."
        )

    # ── OneDrive ─────────────────────────────────────────────────────────────
    if "onedrive" in name_lower or "one drive" in name_lower:
        return (
            "OneDrive sync is widely used in SMB/M365 environments. Disabling file sync may disrupt "
            "business workflows relying on OneDrive for document collaboration. "
            "Evaluate against your data governance policy; consider blocking personal OneDrive instead of business sync."
        )

    # ── App Store / Store apps ────────────────────────────────────────────────
    if "store originated" in name_lower or "store application" in name_lower or "access to the store" in name_lower or "push to install" in name_lower:
        return (
            "Restricting the Microsoft Store prevents users installing unvetted apps. "
            "Appropriate for managed SMB environments. Only allow if specific Store apps are part of approved tooling."
        )

    # ── Advertising ID ────────────────────────────────────────────────────────
    if "advertising id" in name_lower:
        return (
            "Disabling the Advertising ID is a privacy control with no business functionality impact. "
            "Apply the recommended state; no valid operational reason to skip."
        )

    # ── Telemetry / Watson / MSDT / Customer Experience ──────────────────────
    if "watson" in name_lower or "msdt" in name_lower or "customer experience" in name_lower or "error reporting" in name_lower:
        return (
            "Microsoft diagnostic/telemetry features may expose crash data to Microsoft. "
            "Disabling is appropriate for SMBs with data privacy obligations. "
            "Communicate to users that automatic problem reporting will be turned off."
        )
    if "telemetry" in name_lower or "cortana" in name_lower or "input personalization" in name_lower:
        return (
            "Privacy-related restrictions are low-risk for SMBs. Users may notice loss of Cortana/search features. "
            "Acceptable trade-off; communicate change to users to reduce help desk calls."
        )

    # ── Location / cloud search / search highlights ───────────────────────────
    if "location" in name_lower:
        return (
            "Location services on workstations are rarely needed for business functions. "
            "Disabling is low-risk and appropriate for most SMB environments."
        )
    if "cloud search" in name_lower or "search highlights" in name_lower:
        return (
            "Cloud-based search features send query data to Microsoft. "
            "Disabling is low-friction and appropriate for privacy-conscious SMBs. No business search is lost."
        )

    # ── Camera ────────────────────────────────────────────────────────────────
    if "camera" in name_lower:
        return (
            "Blocking camera access at the device level prevents video calls and scanning workflows. "
            "For most SMBs using Teams/Zoom, camera access is required. "
            "Consider per-app permissions instead of a blanket device-level block."
        )

    # ── Cross-device clipboard / shared user data / message sync ─────────────
    if "cross device clipboard" in name_lower or "shared user app data" in name_lower or "message sync" in name_lower:
        return (
            "Cross-device and shared clipboard features can leak data across personal and work devices. "
            "Disabling is low-friction for managed SMB endpoints and reduces data exfiltration risk."
        )

    # ── Upload user activities ────────────────────────────────────────────────
    if "upload user activities" in name_lower:
        return (
            "Activity upload (Timeline) sends usage history to Microsoft. "
            "Disabling is a privacy control with no impact on core business workflows."
        )

    # ── Font providers ────────────────────────────────────────────────────────
    if "font provider" in name_lower:
        return (
            "Online font providers fetch font data from external servers, which can be a minor privacy/security concern. "
            "Blocking is low-risk; only deviate if specific applications depend on online font services."
        )

    # ── Online tips ───────────────────────────────────────────────────────────
    if "online tips" in name_lower:
        return (
            "Online tips connect to Microsoft servers for Settings app suggestions. "
            "Blocking is low-risk and appropriate for managed environments."
        )

    # ── Kerberos certificate-based device auth ────────────────────────────────
    if "device authentication" in name_lower and "certificate" in name_lower:
        return (
            "Certificate-based device authentication strengthens Kerberos and is recommended for Azure AD / Hybrid environments. "
            "Ensure PKI or SCEP/NDES is in place before enabling; misconfiguration can break authentication."
        )

    # ── KMS / AVS validation ──────────────────────────────────────────────────
    if "kms" in name_lower or "avs validation" in name_lower:
        return (
            "KMS online AVS validation contacts Microsoft activation servers. "
            "Disabling is appropriate in air-gapped or privacy-sensitive environments but may affect licensing compliance reporting."
        )

    # ── Enterprise Auth Proxy ─────────────────────────────────────────────────
    if "enterprise auth proxy" in name_lower:
        return (
            "Disabling Enterprise Auth Proxy prevents automatic proxy authentication, "
            "which is low-risk in SMB environments without on-premises proxy infrastructure."
        )

    # ── Wireless / Windows Connect Now ────────────────────────────────────────
    if "connect now" in name_lower or "wireless settings" in name_lower:
        return (
            "Windows Connect Now / WCN wizards can expose Wi-Fi credentials to unauthorised users. "
            "Disabling is low-risk for managed SMB environments using centrally provisioned wireless."
        )

    # ── Printer driver install ────────────────────────────────────────────────
    if "printer" in name_lower and "driver" in name_lower:
        return (
            "Preventing standard users from installing printer drivers reduces the risk of malicious driver installation. "
            "SMBs with shared printers should pre-stage approved drivers via Intune/Group Policy; only deviate if users roam frequently."
        )

    # ── Printing over HTTP ────────────────────────────────────────────────────
    if "printing over http" in name_lower or "print" in name_lower and "http" in name_lower:
        return (
            "Printing over HTTP is a legacy protocol and a potential data interception risk. "
            "Disabling is safe for all managed SMB environments; modern printers use IPP/HTTPS or direct queues."
        )

    # ── Order Prints / Publish to Web / Internet Connection Wizard ───────────
    if "order prints" in name_lower or "publish to web" in name_lower or "internet connection wizard" in name_lower or "registration" in name_lower and "microsoft.com" in name_lower:
        return (
            "Consumer Windows features (Order Prints, Publish to Web, ICW registration) are not relevant to business SMBs. "
            "Disabling is safe and reduces telemetry with no business impact."
        )

    # ── Windows Messenger / Search Companion / Help Experience ───────────────
    if "messenger" in name_lower and "customer experience" in name_lower:
        return (
            "Windows Messenger telemetry is a legacy consumer feature. "
            "Disabling is safe and has no impact on managed SMB endpoints."
        )
    if "search companion" in name_lower or "help experience" in name_lower:
        return (
            "Search Companion and Help Experience Improvement programs are consumer telemetry features. "
            "Disabling is low-risk and appropriate for managed business environments."
        )

    # ── Mapper IO (LLTDIO) / Responder (RSPNDR) drivers ──────────────────────
    if "mapper io" in name_lower or "lltdio" in name_lower or "rspndr" in name_lower or "responder" in name_lower:
        return (
            "LLTD/Responder drivers enable network topology mapping (used by Windows Network Map). "
            "Disabling is appropriate for most SMBs; only enable if network discovery tools explicitly require these drivers."
        )

    # ── Convert Warn To Block / File Hash Computation ────────────────────────
    if "convert warn to block" in name_lower or "file hash" in name_lower:
        return (
            "Defender SmartScreen / file hash settings enhance malware detection with minimal performance impact. "
            "Apply the recommended state; only deviate if a third-party AV/EDR provides equivalent controls."
        )

    # ── Join Microsoft MAPS ────────────────────────────────────────────────────
    if "join microsoft maps" in name_lower or "microsoft maps" in name_lower:
        return (
            "Microsoft MAPS (cloud-based Defender telemetry) improves threat intelligence. "
            "Enable if Defender is the primary AV. Disable if a third-party AV is in place and Defender is passive."
        )

    # ── Remote Encryption Protection ──────────────────────────────────────────
    if "remote encryption" in name_lower:
        return (
            "Remote Encryption Protection detects ransomware encrypting files over network shares. "
            "Enable with the most aggressive setting where possible; test on a pilot group first to confirm no false positives."
        )

    # ── Log On As Batch Job ────────────────────────────────────────────────────
    if "log on as batch job" in name_lower or "batch job" in name_lower:
        return (
            "Batch logon rights should be scoped to specific service accounts only. "
            "Overly broad assignment enables scheduled-task abuse. Audit who holds this right and scope tightly."
        )

    # ── Disallow copying user input methods ───────────────────────────────────
    if "user input methods" in name_lower or "input methods to the system" in name_lower:
        return (
            "Preventing user input methods from being copied to the system account is a low-risk privacy/security control. "
            "No operational impact expected in managed SMB environments."
        )

    # ── Ink Workspace / Spotlight ─────────────────────────────────────────────
    if "ink workspace" in name_lower:
        return (
            "Windows Ink Workspace is a consumer/tablet feature rarely needed in business SMBs. "
            "Disabling is low-risk; only retain if stylus-based workflows are actively used."
        )
    if "spotlight" in name_lower:
        return (
            "Windows Spotlight sends lock screen telemetry to Microsoft. Disabling is low-friction and "
            "appropriate for SMBs with data privacy obligations. No business functionality is lost."
        )

    # ── Clipboard redirection (generic catch) ─────────────────────────────────
    if "clipboard" in name_lower:
        return (
            "Clipboard redirection is commonly needed in RDS/remote work scenarios. "
            "Blocking may frustrate users who copy/paste between local and remote sessions. "
            "Evaluate whether dedicated VDI/RDS use justifies the risk."
        )

    # ── Default fallback — name-aware ─────────────────────────────────────────
    name_words = name_lower.replace("cisv4 - win - l2 - ", "").strip()

    if complexity == "Simple":
        return (
            f"'{name_words}' is a low-complexity, single-value setting with minimal operational impact. "
            "Apply the recommended state; deviation requires a specific documented business or technical exception."
        )
    if complexity == "Moderate":
        return (
            f"'{name_words}' has moderate implementation risk. "
            "Validate against existing tooling and workflows; pilot on a test group before broad rollout."
        )
    return (
        f"'{name_words}' is a complex policy with potential dependencies on other services or tools. "
        "Engage with the client to map dependencies before enforcing. "
        "Use Audit/report-only mode where available; validate then enforce."
    )


# ── Description extraction helpers ───────────────────────────────────────────

# Maps common settingDefinitionId suffixes / value tokens to human-readable labels.
# Used as fallback when the description has no recommended-state sentence.
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
    "_3": "Option 3 (Success and Failure)",
    "_4": "Option 4",
    "_5": "Option 5 (NTLMv2 only, refuse LM & NTLM)",
    "_6": "Option 6",
    "_warn": "Warn",
    "_off": "Off",
    "_on": "On",
    "allowbasicauthentication_service_0": "Disabled",
    "allowbasicauthentication_service_1": "Enabled",
    "allowbasicauthentication_client_0": "Disabled",
    "allowbasicauthentication_client_1": "Enabled",
    "allowunencryptedtraffic_service_0": "Disabled",
    "allowunencryptedtraffic_client_0": "Disabled",
}


def _infer_from_payload(data: dict) -> str:
    """
    Walk the first settingInstance value field and map to a human label.
    Returns a string like 'Disabled (inferred)' or None if unmappable.
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
        # Check specific full-suffix overrides first (longest match wins)
        for suffix, label in sorted(_PAYLOAD_VALUE_MAP.items(), key=lambda x: -len(x[0])):
            if raw_lower.endswith(suffix) or suffix in raw_lower:
                return f"{label} (inferred from payload)"

        # Last resort: strip the definition ID prefix and return the bare token
        token = raw_value.rsplit("_", 1)[-1] if "_" in raw_value else raw_value
        return f"{token} (inferred from payload)"

    except Exception:
        return None


_USER_RIGHTS_KEYWORDS = [
    "access credential manager",
    "act as part of the operating system",
    "create permanent shared objects",
    "create token",
    "enable delegation",
    "lock memory",
    "take ownership",
    "access this computer from the network",
    "allow log on locally",
    "allow log on through remote desktop",
    "back up files and directories",
    "bypass traverse checking",
    "change the system time",
    "create a pagefile",
    "create a token object",
    "create global objects",
    "create symbolic links",
    "debug programs",
    "deny access to this computer",
    "deny log on",
    "force shutdown from a remote system",
    "generate security audits",
    "impersonate a client",
    "increase a process working set",
    "increase scheduling priority",
    "load and unload device drivers",
    "manage auditing and security log",
    "modify an object label",
    "perform volume maintenance tasks",
    "profile single process",
    "profile system performance",
    "replace a process level token",
    "restore files and directories",
    "shut down the system",
    "synchronize directory service data",
    "log on as a batch job",
]


def extract_recommended(description: str, data: dict = None, name: str = "") -> str:
    """
    Extract the 'The recommended state for this setting is: X' sentence.
    Falls back to payload inference if the description is empty or has no match.
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

    # Fallback: infer from configured payload value
    if data is not None:
        inferred = _infer_from_payload(data)
        if inferred:
            return inferred

    # Name-based overrides for policies with no extractable value
    name_lower = name.lower()
    if "message text" in name_lower and ("logon" in name_lower or "log on" in name_lower):
        return "Configure logon banner text (org-specific)"
    if any(kw in name_lower for kw in _USER_RIGHTS_KEYWORDS):
        return "No One / Empty"

    return "N/A"


def clean_description(description: str) -> str:
    """Clean description for CSV — collapse whitespace, strip trailing newlines."""
    cleaned = re.sub(r"\s+", " ", description).strip()
    return cleaned


# ── File parsing ──────────────────────────────────────────────────────────────

def parse_policy_file(filepath: str) -> dict | None:
    """Parse a single policy JSON file and return a dict of fields."""
    try:
        with open(filepath, encoding="utf-16") as f:
            data = json.load(f)
    except Exception:
        # Try utf-8 fallback
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
    complexity = assess_complexity(name, raw_description, setting_count)
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

SAMPLE_MODE = False   # Set False to process ALL policies
SAMPLE_COUNT = 20

# Collect JSON files from root only — no Unmerged Policies subfolder in Level 2
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

output_filename = "CIS_L2_Policy_Summary_SAMPLE.csv" if SAMPLE_MODE else "CIS_L2_Policy_Summary_FULL.csv"
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
