"""
Generate a summary CSV for CIS Intune for Windows Level 1 policies.
Reads from:
  - CIS Microsoft Intune for Windows Level 1 (root .json files)
  - CIS Microsoft Intune for Windows Level 1/Unmerged Policies/ (.json files)
Excludes:
  - CIS Microsoft Intune for Windows Level 1/Merged Policies/

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

    # ASR rules
    if "asr" in name_lower or "attack surface" in name_lower:
        return (
            "ASR rules can break line-of-business apps (e.g., blocking macros in ERP tools). "
            "SMBs should test in Audit mode before enabling Block, or exclude specific trusted apps."
        )
    if "adobe reader" in name_lower:
        return (
            "Some SMB workflows rely on Adobe Reader automations or child processes for PDF workflows. "
            "Recommend Audit mode first; move to Block after validating no legitimate processes break."
        )
    if "psexec" in name_lower or "wmi" in name_lower:
        return (
            "MSP remote management tools (e.g., RMM agents, scripts via WMI/PsExec) may trigger this rule. "
            "Exclusions or Audit mode required before enforcing Block to avoid locking out remote management."
        )
    if "office" in name_lower and ("child" in name_lower or "inject" in name_lower or "executable" in name_lower or "macro" in name_lower):
        return (
            "Many SMB users rely on Office macros for internal automation (invoicing, scheduling). "
            "Blocking may break critical workflows. Audit first; work with client to migrate to safer alternatives."
        )
    if "usb" in name_lower:
        return (
            "Some SMBs use USB drives for legitimate data transfer or POS/line-of-business devices. "
            "Blanket USB blocking may disrupt operations. Restrict by device type instead of a full block."
        )
    if "ransomware" in name_lower:
        return (
            "The ransomware protection ASR rule can interfere with backup agents writing to protected folders. "
            "Verify backup software compatibility and add exclusions before enforcing."
        )

    # Firewall policies
    if "firewall" in name_lower:
        if "log" in name_lower:
            return (
                "Firewall logging generates significant disk I/O on low-spec SMB endpoints. "
                "May be acceptable to disable verbose logging on non-critical workstations if storage is constrained."
            )
        if "inbound" in name_lower or "default inbound" in name_lower:
            return (
                "Block-all-inbound is correct for most SMBs, but may break peer-to-peer apps, "
                "shared printers, or RDP without explicit allow rules in place. Verify rules before enforcing."
            )
        if "notification" in name_lower:
            return (
                "Suppressing firewall notifications is fine for managed endpoints, but SMB users "
                "may miss alerts about blocked software they legitimately need. Low risk to accept recommended."
            )
        return (
            "Enabling all three firewall profiles is strongly recommended. "
            "Only deviate if a third-party firewall (e.g., Sophos, SentinelOne) is centrally managed and verified active."
        )

    # Audit / Event Log policies
    if "audit" in name_lower or "event log" in name_lower or "log file size" in name_lower:
        if "log file size" in name_lower or "maximum log" in name_lower or "specify the maximum" in name_lower:
            return (
                "Default log sizes may be sufficient for small SMBs not running a SIEM. "
                "Increasing log sizes consumes disk space on constrained endpoints; balance with retention needs."
            )
        if "success and failure" in recommended.lower() or "success" in recommended.lower():
            return (
                "Full audit logging (Success and Failure) can generate high event volume on busy systems, "
                "impacting SIEM ingestion costs. For SMBs without a SIEM, Failure-only auditing is a pragmatic compromise."
            )
        return (
            "Audit policies are low-risk to enable and strongly recommended for incident response. "
            "Only skip if event log storage or SIEM capacity is a documented constraint."
        )

    # Network security / NTLM / LM
    if "lan manager" in name_lower or "ntlm" in name_lower or "ntlmssp" in name_lower:
        return (
            "Enforcing NTLMv2-only or disabling LM/NTLM can break older network devices, NAS appliances, "
            "or legacy line-of-business apps that don't support modern auth. Audit NTLM usage first via Event Log 4776."
        )
    if "pku2u" in name_lower:
        return (
            "PKU2U is rarely needed in SMB environments. Disabling is low-risk and recommended. "
            "Only deviate if peer-to-peer HomeGroup-style sharing is in use (uncommon in managed environments)."
        )
    if "network access" in name_lower and "anonymous" in name_lower:
        return (
            "Anonymous enumeration blocks are important but can break some legacy scan-to-folder or "
            "print workflows on older MFPs. Verify printer/scanner compatibility before enforcing."
        )
    if "restrict clients allowed" in name_lower or "remote calls to sam" in name_lower:
        return (
            "Restricting SAM remote calls is strongly recommended. Only skip if an RMM or monitoring "
            "tool explicitly requires legacy SAM access — contact the vendor for a modern alternative."
        )
    if "lsa" in name_lower and "protected" in name_lower:
        return (
            "LSA protection with UEFI lock is the gold standard but can block some AV/EDR drivers on older endpoints. "
            "Test in a non-production group first; some agents may need updating before enforcement."
        )

    # Device password / lock
    if "device password" in name_lower or "device lock" in name_lower:
        if "expiration" in name_lower:
            return (
                "Password expiration policies can frustrate SMB users and lead to predictable password patterns. "
                "Many security frameworks now recommend long passphrases without mandatory expiration unless compromised."
            )
        if "history" in name_lower:
            return (
                "Password history is low-friction and strongly recommended. "
                "Only skip for kiosk/shared accounts where history tracking is not feasible."
            )
        if "failed attempts" in name_lower or "lockout" in name_lower:
            return (
                "Aggressive lockout thresholds (e.g., 5 attempts) can trigger denial-of-service by malicious insiders. "
                "SMBs without help desk coverage may struggle with lockout resolution; balance threshold with support capacity."
            )
        if "inactivity" in name_lower or "lock" in name_lower:
            return (
                "Short screen lock timeouts frustrate workers in non-sensitive shared spaces. "
                "15-minute timeout may be acceptable for SMBs; CIS recommends shorter but 15 min is a pragmatic balance."
            )
        return (
            "Device password enforcement is foundational. Only deviate for kiosk or single-purpose devices "
            "where a PIN/biometric alternative is in use and documented."
        )

    # UAC policies
    if "uac" in name_lower or "user account control" in name_lower or "elevation" in name_lower:
        if "standard users" in name_lower:
            return (
                "Auto-denying elevation for standard users is ideal but can frustrate SMB users who "
                "occasionally need to install software. Ensure a clear IT escalation path is in place."
            )
        if "administrator" in name_lower and "elevation" in name_lower:
            return (
                "Prompting admins for credentials (not just consent) is the most secure option but adds friction "
                "for IT staff performing frequent admin tasks on SMB endpoints. Consent prompt is an acceptable middle ground."
            )
        return (
            "UAC settings are low-disruption and strongly recommended. "
            "Only skip for break-glass/admin-only workstations where UAC is superseded by other controls."
        )

    # WinRM
    if "winrm" in name_lower or "winrm client" in name_lower or "winrm service" in name_lower:
        return (
            "Disabling basic/unencrypted WinRM is critical — however, some RMM tools or legacy scripts "
            "may depend on it. Audit WinRM usage before enforcing; migrate to HTTPS/Kerberos-based WinRM."
        )

    # User rights / privilege assignments (Access From Network, Act As OS, etc.)
    if "access from network" in name_lower:
        return (
            "Restricting network logon rights to Administrators and Remote Desktop Users is correct for most SMBs. "
            "Deviating would only be needed if a specific service account or legacy app requires broader network access — "
            "document the exception and scope it tightly."
        )
    if "act as part of the operating system" in name_lower:
        return (
            "This privilege should be granted to no accounts (empty) in virtually all SMB environments. "
            "No legitimate user or standard service requires it; deviation is a significant security risk."
        )
    if "backup files" in name_lower or "backup directory" in name_lower:
        return (
            "Backup rights should be scoped to the backup service account only. "
            "If a third-party backup agent is in use, verify it runs under a dedicated least-privilege account rather than a broad group."
        )
    if "create global objects" in name_lower:
        return (
            "This right is needed by some RMM agents and session management services. "
            "Verify whether your RMM or monitoring platform requires it before removing; check vendor documentation."
        )
    if "create page file" in name_lower or "create permanent" in name_lower or "create symbolic" in name_lower:
        return (
            "These are low-use rights that should stay restricted to Administrators. "
            "Deviation is rarely needed; only grant if a specific documented service dependency requires it."
        )
    if "change system time" in name_lower:
        return (
            "Time sync should be managed centrally (e.g., domain or Intune NTP policy). "
            "Restricting manual time changes to LOCAL SERVICE and Administrators is correct for managed SMB endpoints."
        )

    # Accounts policies
    if "rename administrator" in name_lower or "rename guest" in name_lower:
        return (
            "Renaming built-in accounts is a low-effort hardening step. The policy applies the rename via Intune. "
            "No operational justification exists to skip this; deviation only increases attack surface for local account brute-force."
        )
    if "blank passwords" in name_lower or "blank  passwords" in name_lower:
        return (
            "Allowing blank passwords only at the console is a foundational control with no meaningful operational downside. "
            "Only a kiosk with a documented exception process would warrant deviation."
        )
    if "guest account" in name_lower:
        return (
            "The Guest account should always be disabled in managed SMB environments. "
            "No legitimate use case justifies enabling it when Intune manages device access."
        )
    if "microsoft accounts" in name_lower and "optional" in name_lower:
        return (
            "Making Microsoft accounts optional prevents users bypassing corporate credentials. "
            "Only deviate if the tenant uses Microsoft consumer accounts as the primary identity (rare in managed SMB)."
        )

    # Credential Manager / SAM / specific privileges
    if "credential manager" in name_lower:
        return (
            "Restricting Credential Manager access is low-friction for most SMB users. "
            "Only deviate if a specific SSO or password manager integration requires this privilege."
        )

    # SMB / RPC
    if "smb v1" in name_lower:
        return (
            "Disabling SMBv1 is strongly recommended — it is exploited by ransomware (WannaCry, NotPetya). "
            "Only deviate if a legacy NAS/device requires it; replace the device instead."
        )
    if "rpc" in name_lower:
        return (
            "RPC hardening settings are generally safe but can break some older printer or file share workflows. "
            "Test on a pilot group before broad deployment."
        )

    # Remote Assistance
    if "remote assistance" in name_lower or "offer remote" in name_lower or "solicited remote" in name_lower:
        return (
            "Remote Assistance is rarely used in MSP-managed SMB environments where RMM tools are in place. "
            "Disabling is low-risk; only retain if end-users actively use RA for peer-to-peer help sessions."
        )

    # Telemetry / Privacy
    if "telemetry" in name_lower or "cortana" in name_lower or "input personalization" in name_lower or "location" in name_lower:
        return (
            "Privacy-related restrictions are low-risk for SMBs. Users may notice loss of Cortana/search features. "
            "Acceptable trade-off; communicate change to users to reduce help desk calls."
        )

    # Defender / Antivirus
    if "defender" in name_lower or "scanning" in name_lower or "monitoring" in name_lower or "realtime" in name_lower or "maps" in name_lower:
        return (
            "Defender settings should match the recommended state in most SMB environments. "
            "Only deviate if a third-party AV (e.g., Sophos, CrowdStrike) replaces Defender — confirm AV is active and managed."
        )

    # SmartScreen
    if "smartscreen" in name_lower:
        return (
            "SmartScreen is low-friction and strongly recommended for SMBs. "
            "Only skip if a third-party web filter (e.g., DNS filtering) already provides equivalent protection."
        )

    # App Store / Updates
    if "auto update" in name_lower or "allow auto update" in name_lower:
        return (
            "Windows Update should be managed via an Intune Update Ring policy, not this setting alone. "
            "Ensure an update ring is configured and targeting the device before changing this toggle, "
            "otherwise devices may stop receiving patches."
        )
    if "app store" in name_lower or "apps from the microsoft app store" in name_lower:
        return (
            "Allowing Microsoft Store apps to auto-update is generally low-risk and reduces the patch burden on IT. "
            "Only disable if a specific Store app version must be pinned for compatibility reasons."
        )
    if "allow networking" in name_lower:
        return (
            "This policy controls whether networking is available during OOBE/provisioning. "
            "Required for Autopilot and cloud-join scenarios — do not disable in Intune-managed SMB environments."
        )

    # Indexing / Search privacy
    if "indexing encrypted" in name_lower:
        return (
            "Indexing encrypted files can expose sensitive content via the search index. Blocking is the correct default. "
            "Only enable if users actively search encrypted files and accept the security trade-off."
        )
    if "search to use location" in name_lower:
        return (
            "Location access for search is unnecessary in most SMB environments and raises privacy concerns. "
            "Blocking has no impact on business search functionality."
        )

    # Apply UAC to local accounts on network logons
    if "uac restrictions" in name_lower and "local accounts" in name_lower:
        return (
            "Applying UAC token filtering to local accounts prevents pass-the-hash lateral movement. "
            "Only skip if a legacy monitoring tool authenticates via local admin over the network — replace with a domain or service account."
        )

    # Block consumer Microsoft accounts
    if "block all consumer microsoft" in name_lower or "consumer microsoft account" in name_lower:
        return (
            "Blocking consumer Microsoft account authentication prevents users from signing into business apps "
            "with personal accounts. Essential for data governance in SMBs using Microsoft 365. No valid business reason to skip."
        )

    # Block non-admin install / UWP / launching Universal Windows apps
    if "block non admin" in name_lower or "non-admin user install" in name_lower:
        return (
            "Preventing non-admin software installs is a key control for SMBs where users may inadvertently install malware. "
            "Only deviate for power users with a documented need and compensating controls (e.g., application allowlisting)."
        )
    if "universal windows apps" in name_lower or "windows runtime api" in name_lower:
        return (
            "Blocking UWP apps from hosted content prevents web-based exploits from launching store apps. "
            "Low operational impact for most SMBs; only skip if a specific UWP-based LOB app depends on this behaviour."
        )
    if "block user from showing account details" in name_lower:
        return (
            "Hiding account details on the sign-in screen prevents username enumeration. "
            "No impact on user experience after sign-in; deviation is not recommended."
        )

    # Continue experiences (Handoff)
    if "continue experiences" in name_lower:
        return (
            "Cross-device continuity features (phone-to-PC handoff) are a consumer feature rarely needed in SMB. "
            "Disabling reduces data exposure with no business productivity loss."
        )

    # Spotlight Collection
    if "spotlight" in name_lower:
        return (
            "Spotlight Collection sends lock screen telemetry to Microsoft. Disabling is low-friction and "
            "appropriate for SMBs with data privacy obligations. No business functionality is lost."
        )

    # Ink Workspace / Game DVR / widgets
    if "ink workspace" in name_lower or "game dvr" in name_lower or "widget" in name_lower:
        return (
            "Disabling consumer features (Game DVR, Ink Workspace, Widgets) is low-risk for business SMBs "
            "and reduces attack surface. Only retain if a specific business use case depends on these features."
        )

    # Clipboard Redirection / RDP
    if "clipboard" in name_lower or "rdp" in name_lower or "remote desktop" in name_lower:
        return (
            "Clipboard redirection is commonly needed in RDS/remote work scenarios. "
            "Blocking may frustrate users who copy/paste between local and remote sessions. "
            "Evaluate whether dedicated VDI/RDS use justifies the risk."
        )

    # Default fallback — name-aware
    name_words = name_lower.replace("cisv4 - win - l1 - ", "").strip()

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

SAMPLE_MODE = True   # Set False to process ALL policies
SAMPLE_COUNT = 20

# Collect JSON files from root and Unmerged Policies, exclude Merged Policies
root_files = glob.glob(os.path.join(BASE_DIR, "*.json"))
unmerged_files = glob.glob(os.path.join(BASE_DIR, "Unmerged Policies", "*.json"))

all_files = sorted(root_files + unmerged_files)
print(f"Total JSON files found: {len(all_files)}")

rows = []
for fp in all_files:
    result = parse_policy_file(fp)
    if result:
        rows.append(result)
    if SAMPLE_MODE and len(rows) >= SAMPLE_COUNT:
        break

print(f"Rows parsed: {len(rows)}")

output_filename = "CIS_L1_Policy_Summary_SAMPLE.csv" if SAMPLE_MODE else "CIS_L1_Policy_Summary_FULL.csv"
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
