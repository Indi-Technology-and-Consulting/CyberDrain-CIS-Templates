"""
Generate a summary CSV for CIS Intune for Windows BitLocker policies (CISv4 IFW BL).
Reads from:
  - CISv4 Intune for Windows Bitlocker Benchmarks (root .json files only)

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
    # BitLocker-specific complex triggers
    "tpm",                     # TPM startup authentication options
    "cipher strength",         # Encryption algorithm selection
    "recovery",                # Recovery key/password configuration
    "recovered",               # Parent recovery enable policies
    "require additional authentication",  # Parent startup auth policy
    "device setup class",      # Device installation class restrictions
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
    # BitLocker-specific moderate triggers
    "bitlocker",               # General BitLocker policies
    "encryption",              # Drive encryption settings
    "removable",               # Removable drive policies
    "fixed drive",             # Fixed data drive policies
    "operating system drive",  # OS drive policies
    "allow warning",           # Warning suppression for disk encryption
    "deny write",              # Write access restrictions
    "device enumeration",      # Device enumeration policy
    "prevent installation",    # Device installation restrictions
]


def assess_complexity(name: str, description: str, setting_count: int) -> str:
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

    # ── Require Device Encryption ─────────────────────────────────────────────
    if "require device encryption" in name_lower:
        return (
            "BitLocker Device Encryption is a foundational control for data-at-rest protection. "
            "Enable on all managed endpoints. The only valid deviation is for devices with hardware "
            "incompatibilities (e.g., no TPM chip); document and treat as exception with compensating controls."
        )

    # ── Allow Warning For Other Disk Encryption ────────────────────────────────
    if "allow warning for other disk encryption" in name_lower:
        if "standard user" in name_lower:
            return (
                "Allowing standard users to enable BitLocker without admin involvement streamlines deployment "
                "in SMB environments with limited IT resources. Evaluate whether silent encryption (no user prompt) "
                "is preferred; if so, set Allow Standard User Encryption to Block."
            )
        return (
            "Disabling the warning prompt for other disk encryption enables silent BitLocker deployment. "
            "Required for Autopilot and zero-touch enrollment scenarios. "
            "Confirm no third-party disk encryption (e.g., VeraCrypt) is in use before enforcing."
        )

    # ── Choose drive encryption method and cipher strength ────────────────────
    if "cipher strength" in name_lower or "encryption method" in name_lower:
        if "removable" in name_lower:
            return (
                "XTS-AES 128-bit is the CIS-recommended cipher for removable drives. "
                "Note: XTS-AES is not compatible with older Windows versions or non-Windows systems reading the drive. "
                "If cross-platform or cross-version USB access is required, consider AES-CBC 128-bit instead."
            )
        if "operating system" in name_lower:
            return (
                "XTS-AES 256-bit provides the strongest protection for the OS drive and is the CIS recommendation. "
                "No valid operational reason to downgrade in a managed SMB environment. "
                "Deviation should be documented with a specific technical justification."
            )
        return (
            "XTS-AES 128-bit (or higher) is the CIS-recommended cipher for fixed data drives. "
            "Only deviate if compatibility with legacy tooling requires a different algorithm. "
            "Document cipher choice and review annually."
        )

    # ── Recovery options — OS drives ──────────────────────────────────────────
    if "operating system drives can be recovered" in name_lower or (
        "operating system" in name_lower and "recovery" in name_lower
    ):
        if "recovery key" in name_lower or "256-bit" in name_lower:
            return (
                "Controlling whether recovery keys are displayed or printed limits exposure. "
                "For SMBs using Intune/Azure AD, recovery keys are escrowed automatically to Azure AD — "
                "this is the preferred recovery path; disable user-visible key display unless needed."
            )
        if "recovery password" in name_lower:
            return (
                "Recovery passwords provide a 48-digit fallback for OS drive recovery. "
                "Requiring the password to be generated ensures users always have a recovery path. "
                "For Intune-managed devices, passwords are stored in Azure AD; "
                "disable user-printable passwords and rely on IT-retrieved keys."
            )
        if "data recovery agent" in name_lower:
            return (
                "Data Recovery Agents (DRAs) allow domain admins to decrypt drives using a certificate. "
                "For pure Azure AD / Intune environments without on-premises AD, DRAs are not applicable. "
                "Leave disabled unless on-premises AD DRA infrastructure is in place."
            )
        if "omit recovery options" in name_lower or "wizard" in name_lower:
            return (
                "Omitting recovery options from the BitLocker setup wizard prevents users from making "
                "uninformed choices about key escrow. IT should control recovery option visibility. "
                "Ensure recovery keys are already being escrowed to Azure AD before enforcing."
            )
        return (
            "BitLocker OS drive recovery options are critical for business continuity. "
            "Ensure recovery keys are escrowed to Azure AD before enforcing. "
            "Test recovery procedure in a lab before broad deployment."
        )

    # ── Recovery options — Fixed drives ───────────────────────────────────────
    if "fixed" in name_lower and "recovered" in name_lower:
        if "recovery key" in name_lower:
            return (
                "Recovery key display/print options for fixed drives should be restricted. "
                "Keys escrowed to Azure AD via Intune are the preferred recovery path for SMBs. "
                "Disable user-visible key generation unless IT cannot access Azure AD portal."
            )
        if "recovery password" in name_lower:
            return (
                "48-digit recovery passwords for fixed drives provide a fallback alongside Azure AD escrow. "
                "Requiring password generation ensures recoverability; disable user-printable display "
                "and rely on IT portal retrieval."
            )
        if "data recovery agent" in name_lower:
            return (
                "DRA support for fixed drives requires on-premises AD DRA certificates. "
                "Not applicable in pure cloud (Intune/Azure AD) environments. "
                "Leave disabled unless DRA infrastructure exists."
            )
        if "omit recovery options" in name_lower or "wizard" in name_lower:
            return (
                "Omitting recovery options from the BitLocker setup wizard for fixed drives prevents "
                "uninformed user choices. Ensure Azure AD escrow is active before enforcing this restriction."
            )
        if "ad ds" in name_lower or "active directory" in name_lower or "storage of bitlocker" in name_lower:
            return (
                "Storing BitLocker recovery information in AD DS (Active Directory) is relevant for "
                "on-premises or hybrid environments. For pure Azure AD / Intune environments, "
                "recovery keys are escrowed to Azure AD automatically — this AD DS setting may not apply. "
                "Validate your identity topology before enforcing."
            )
        return (
            "Fixed drive recovery configuration is critical for data-at-rest recovery workflows. "
            "Ensure Azure AD escrow is confirmed working before locking down recovery options. "
            "Pilot on a subset of devices first."
        )

    # ── Require additional authentication at startup ───────────────────────────
    if "require additional authentication at startup" in name_lower:
        if "tpm startup pin" in name_lower and "key" not in name_lower:
            return (
                "Requiring a TPM startup PIN adds a second factor (something-you-know) to BitLocker. "
                "This is the highest-assurance configuration but adds friction at every boot. "
                "For SMBs with unattended servers or kiosk devices, a PIN may not be practical; "
                "evaluate TPM-only for those device classes and TPM+PIN for user workstations."
            )
        if "tpm startup key and pin" in name_lower:
            return (
                "TPM + startup key + PIN is the most restrictive configuration and requires a USB key at every boot. "
                "Impractical for most SMB workstations; typically only used in high-security environments. "
                "Evaluate against your operational model before enforcing."
            )
        if "tpm startup key" in name_lower:
            return (
                "Requiring a TPM startup key (USB) adds a physical second factor to BitLocker. "
                "Operational overhead is high; suitable for high-security or regulated environments. "
                "Evaluate TPM-only or TPM+PIN as more practical alternatives for most SMBs."
            )
        if "configure tpm startup" in name_lower:
            return (
                "Configuring TPM-only startup (no PIN or key) provides transparent encryption with no user friction. "
                "Suitable for most SMB workstations managed via Intune. "
                "Consider adding a PIN for high-risk user populations (executives, remote workers)."
            )
        return (
            "BitLocker startup authentication configuration balances security and usability. "
            "For most SMBs, TPM-only is the recommended baseline. "
            "Add PIN or startup key for higher-risk device classes; document exceptions."
        )

    # ── Enforce drive encryption type on OS drives ────────────────────────────
    if "enforce drive encryption type" in name_lower or "encryption type" in name_lower:
        return (
            "Full disk encryption (vs. used-space-only) provides stronger protection against offline forensic tools. "
            "Full encryption takes longer on initial setup. For new Autopilot deployments, used-space-only "
            "is acceptable since drives are fresh. For re-provisioned devices, prefer full disk encryption "
            "to ensure deleted data is not recoverable."
        )

    # ── Deny write access to removable drives ─────────────────────────────────
    if "deny write access to removable drives" in name_lower:
        return (
            "Blocking writes to unprotected removable drives prevents data exfiltration via USB. "
            "This is a strong data-loss-prevention control with potential operational impact: "
            "users cannot write to unencrypted USB drives. "
            "Communicate this policy to users and provide BitLocker-encrypted USB drives for approved use cases."
        )

    # ── Device Enumeration Policy ──────────────────────────────────────────────
    if "device enumeration policy" in name_lower:
        return (
            "Blocking all external DMA-capable devices (PCIe, Thunderbolt) prevents DMA-based hardware attacks. "
            "This is the most restrictive setting and may block docking stations and some peripherals. "
            "Test with all approved hardware before enforcing; document approved device exceptions."
        )

    # ── Prevent installation of devices using drivers (device setup classes) ──
    if "prevent installation of devices" in name_lower or "device setup class" in name_lower:
        return (
            "Blocking device installation by setup class prevents unauthorised hardware (e.g., rogue USB storage) "
            "from being installed by standard users. "
            "Ensure all approved device classes are excluded via the allow-list before enforcing; "
            "work with the client to identify any business-critical device classes that must be permitted."
        )

    # ── Generic BitLocker fallback ─────────────────────────────────────────────
    if "bitlocker" in name_lower or "encryption" in name_lower or "recovery" in name_lower:
        return (
            "BitLocker policies are foundational for data-at-rest compliance. "
            "Apply the recommended state; deviations require a documented technical or operational exception. "
            "Verify Azure AD key escrow is functioning before enforcing any BitLocker policy."
        )

    # ── Default fallback — name-aware ─────────────────────────────────────────
    name_words = re.sub(r"^cisv?4\s*-\s*ifw\s*-\s*bl\s*-\s*", "", name_lower).strip()

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

SAMPLE_MODE = False   # Change to True for sample run (first 20 policies)
SAMPLE_COUNT = 20

# Collect JSON files from root only — no Unmerged Policies subfolder in BitLocker
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

output_filename = "CIS_BL_Policy_Summary_SAMPLE.csv" if SAMPLE_MODE else "CIS_BL_Policy_Summary_FULL.csv"
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
