# CIS Intune Policy Summary CSV — Master Context & Rules

Applies to all `generate_summary_csv.py` scripts across CIS benchmark levels.
Level-specific details are called out explicitly where they differ.

---

## What we build

A Python script (`generate_summary_csv.py`) lives in each CIS level folder.
It reads all CIS Intune for Windows policy JSON files for that level and produces a summary CSV.
An optional `format_spreadsheet.py` converts the CSV to a formatted Excel workbook.

---

## Folder layout per level

```
CIS Microsoft Intune for Windows Level N\
    generate_summary_csv.py
    *.json                          ← included (root-level policies)
    Unmerged Policies\*.json        ← included (Level 1 ONLY)
    Merged Policies\                ← EXCLUDED (Level 1 ONLY)
    Summary CSV\
        CONTEXT_SUMMARY.md
        CIS_LN_Policy_Summary_SAMPLE.csv
        CIS_LN_Policy_Summary_FULL.csv

CISv4 Intune for Windows Bitlocker Benchmarks\
    generate_summary_csv.py
    *.json                          ← included (root-level policies only)
    Summary CSV\
        CIS_BL_Policy_Summary_SAMPLE.csv
        CIS_BL_Policy_Summary_FULL.csv

CIS Microsoft Intune for Windows Level  Bitlocker\   ← older BL folder
    generate_summary_csv.py
    *.json                          ← included (root-level policies only)
    Summary CSV\
        CIS_LBL_Policy_Summary_SAMPLE.csv
        CIS_LBL_Policy_Summary_FULL.csv

CISv3 Microsoft Edge Level 1 Benchmark\
    generate_summary_csv.py
    *.json                          ← included (root-level policies only)
    Summary CSV\
        CIS_EDGE_L1_Policy_Summary_SAMPLE.csv
        CIS_EDGE_L1_Policy_Summary_FULL.csv
```

> **Note:** There are two BitLocker folders in the repo:
> - `CIS Microsoft Intune for Windows Level  Bitlocker\` — older folder (output prefix `CIS_LBL_`); script lacks the `"recovered"` and `"require additional authentication"` COMPLEX_KEYWORDS that were added to the newer script
> - `CISv4 Intune for Windows Bitlocker Benchmarks\` — current folder, 16 policies, script created 2026-02-19 (output prefix `CIS_BL_`)
>
> Also note: one JSON filename in the new BL folder uses `CIS4v` (digits before `v`) instead of `CISv4`.
> The prefix-strip regex accounts for this: `^cisv?4\s*-\s*ifw\s*-\s*bl\s*-\s*`

### Per-level source folders

| Level | Root JSON | Unmerged Policies\ | Merged Policies\ | Total policies |
|---|---|---|---|---|
| L1 | YES | YES | NO (excluded) | 316 |
| L2 | YES | N/A (folder doesn't exist) | N/A | 63 |
| BL (BitLocker, new) | YES | N/A | N/A | 16 |
| BL (BitLocker, old) | YES | N/A | N/A | varies |
| Edge L1 (CISv3) | YES | N/A | N/A | varies |

---

## SAMPLE_MODE flag

Each script has a `SAMPLE_MODE` boolean at the top:

```python
SAMPLE_MODE = True   # Change to False for full run
```

- `True` → first 20 policies only → `CIS_LN_Policy_Summary_SAMPLE.csv`
- `False` → all policies → `CIS_LN_Policy_Summary_FULL.csv`

> **Exception:** The Edge L1 script defaults to `SAMPLE_MODE = False` — it runs the full set by default.

---

## CSV column definitions (identical across levels)

| Col | Header | Source / Logic |
|---|---|---|
| A | `Name` | JSON `name` field |
| B | `Description` | JSON `description` field, whitespace-collapsed |
| C | `Recommended Setting` | Description extraction → payload inference → name override → `N/A` |
| D | `Complexity` | Heuristic: Simple / Moderate / Complex (name-based + settingCount) |
| E | `SMB Justification (if not using recommended)` | Pre-filled SMB/MSP deviation rationale |

---

## Column C — Recommended Setting extraction (3-stage pipeline)

### Stage 1: description sentence extraction
```
The recommended state for this setting is[:\s]+(.+?)(?:\.|$)
```
Applied to the raw `description` field. Captured value has whitespace/newlines collapsed.

### Stage 2: payload inference (when Stage 1 produces no match)
Reads `settings[0].settingInstance`:
1. `choiceSettingValue` → reads `.value` token, maps via `_PAYLOAD_VALUE_MAP`
2. `groupSettingCollectionValue` → reads first child's `choiceSettingValue.value`
3. `simpleSettingValue` → returns raw integer/string as `X (configured value)`

Inferred values are tagged `X (inferred from payload)` for spot-checking.

#### `_PAYLOAD_VALUE_MAP` token → label mappings (shared across levels)
| Token suffix | Label |
|---|---|
| `_block` | Block |
| `_0` | Disabled / Off |
| `_1` | Enabled / On |
| `_true` | Enabled (True) |
| `_false` | Disabled (False) |
| `_3` | Option 3 (Success and Failure) |
| `_5` | Option 5 (NTLMv2 only, refuse LM & NTLM) |
| Named full-token strings (e.g. `allowbasicauthentication_service_0`) | Disabled |

Expand `_PAYLOAD_VALUE_MAP` to add level-specific or policy-specific numeric labels.

### Stage 3: name-based overrides (when Stages 1–2 both fail)
| Name pattern | Returns |
|---|---|
| `"message text"` + (`"logon"` or `"log on"`) | `Configure logon banner text (org-specific)` |
| Any entry in `_USER_RIGHTS_KEYWORDS` | `No One / Empty` |

`_USER_RIGHTS_KEYWORDS` covers all Windows user-rights assignment policy names.
L1 set: `"access credential manager"`, `"act as part of the operating system"`, `"create token"`,
`"enable delegation"`, `"lock memory"`, `"take ownership"`, and ~30 more.
L2 set: includes `"log on as a batch job"`, `"allow log on through remote desktop"`, etc.

> **Edge L1 exception:** Stage 3 is not implemented in the Edge script. After payload inference
> (Stage 2) fails, `extract_recommended` returns `N/A` immediately. Edge policies don't include
> Windows logon banner or user-rights assignment policy types, so Stage 3 is not needed.

### Final fallback
Returns `N/A`. Target: **0 rows at N/A** after a full run.

---

## Column D — Complexity keywords

Keywords are matched against `name.lower()` only (never the description prose).
Secondary signal: `settingCount` from JSON.

### Complex triggers

**Shared (L1 + L2):**
```
"asr", "attack surface reduction",
"ntlm", "ntlmssp", "lan manager",
"pku2u", "wmi", "psexec",
"lsa protected", "lsa process",
"kerberos", "sam account",
"rpc", "smb v1",
"redirection guard",
"system guard", "boot-start driver",
"config refresh"
```
OR `settingCount > 3`

**L2 additions:**
```
"powershell",
"mss", "tcp",
"mapper io", "lltdio", "rspndr"
```

**BL (BitLocker) additions:**
```
"tpm",
"cipher strength",
"recovery",
"recovered",
"require additional authentication"
```

> **Note:** `"recovered"` is distinct from `"recovery"` — needed to catch parent-enable policies
> whose names end in `"...can be recovered is set to Enabled"` (no "recovery" substring).
> `"require additional authentication"` uses a shortened form because the JSON name field contains
> a double space (`"at  startup"`) that breaks a full-phrase keyword match.
>
> **Older BL folder difference:** `CIS Microsoft Intune for Windows Level  Bitlocker\generate_summary_csv.py`
> does NOT include `"recovered"` or `"require additional authentication"` in its COMPLEX_KEYWORDS.
> It also includes `"device setup class"` as a complex keyword (not present in the newer BL script).

**Edge L1 (CISv3) additions:**
```
"site isolation",
"legacy extension point",
"audio sandbox",
"remote debugging",
"hsts",
"webrtc",
"insecure content",
"experimentation and configuration"
```

### Moderate triggers

**Shared (L1 + L2):**
```
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
"ipsec"
```
OR `settingCount > 1`

**L2 additions:**
```
"remote desktop", "rdp",
"remote shell",
"onedrive", "one drive",
"store",
"watson", "msdt",
"kms",
"enterprise auth proxy",
"connect now",
"plug and play",
"print", "printer",
"ink workspace",
"spotlight"
```

**BL (BitLocker) additions:**
```
"bitlocker",
"encryption",
"removable",
"fixed drive",
"operating system drive",
"allow warning",
"deny write",
"device enumeration",
"prevent installation"
```

**Edge L1 (CISv3) additions:**
```
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
"background apps"
```

> **Note:** The Edge script's `assess_complexity` function signature omits the `description` parameter
> (only `name` and `setting_count` are passed). This is intentional — Edge policy descriptions are
> not used as a complexity signal.

### Simple — everything else

### Full-run complexity breakdown

| Tier | L1 (316 policies) | L2 (63 policies) | BL (16 policies) | Edge L1 |
|---|---|---|---|---|
| Simple | 186 (58.9%) | 36 (57.1%) | 0 (0%) | TBD |
| Moderate | 91 (28.8%) | 18 (28.6%) | 0 (0%) | TBD |
| Complex | 39 (12.3%) | 9 (14.3%) | 16 (100%) | TBD |

---

## Column E — SMB Justification rules

Matched by `name.lower()` in priority order. Rules are cumulative across levels —
L2 adds new categories on top of the L1 set.

### L1 justification categories (in match order)

| Pattern | Justification theme |
|---|---|
| `asr` / `attack surface` | Test in Audit mode first; LOB app compatibility risk |
| `adobe reader` | PDF workflow child process dependencies |
| `psexec` / `wmi` | RMM agent conflicts; Audit before Block |
| `office` + `child/inject/executable/macro` | Office macro dependencies in SMB |
| `usb` | USB device type — restrict, don't blanket-block |
| `ransomware` | Backup agent conflicts with ransomware ASR rule |
| `firewall` + `log` | Disk I/O on low-spec endpoints |
| `firewall` + `inbound` | Verify allow rules before enforcing Block |
| `firewall` + `notification` | Users may miss alerts |
| `firewall` (generic) | Third-party firewall caveat |
| `audit` / `event log` / `log file size` | SIEM cost / disk space on small SMBs |
| `lan manager` / `ntlm` / `ntlmssp` | Legacy device/NAS NTLMv2 compatibility |
| `pku2u` | HomeGroup/peer-to-peer caveat (rare) |
| `network access` + `anonymous` | Legacy MFP scan-to-folder |
| `restrict clients allowed` / `remote calls to sam` | RMM legacy SAM access |
| `lsa` + `protected` | AV/EDR driver compatibility |
| `device password` + `expiration` | Password expiration frustration / NIST guidance |
| `device password` + `history` | Kiosk/shared account exception |
| `device password` + `failed attempts`/`lockout` | Lockout DoS by insiders |
| `device password` + `inactivity`/`lock` | 15-min timeout pragmatic balance |
| `device password` (generic) | Kiosk/biometric exception |
| `uac` / `user account control` / `elevation` + `standard users` | IT escalation path needed |
| `uac` + `administrator` + `elevation` | Credential vs consent prompt trade-off |
| `uac` (generic) | Break-glass exception only |
| `winrm` | RMM tool dependency; migrate to HTTPS/Kerberos |
| `access from network` | Service account / legacy app exception |
| `act as part of the operating system` | Should be empty; deviation = significant risk |
| `backup files` / `backup directory` | Least-privilege backup service account |
| `create global objects` | RMM agent session management dependency |
| `create page file` / `create permanent` / `create symbolic` | Restrict to Admins; deviation rare |
| `change system time` | Central NTP management |
| `rename administrator` / `rename guest` | No valid reason to skip |
| `blank passwords` | Foundational; kiosk exception only |
| `guest account` | Always disable in managed SMB |
| `microsoft accounts` + `optional` | Corporate identity governance |
| `credential manager` | SSO/password manager exception |
| `smb v1` | WannaCry/NotPetya; replace legacy device |
| `rpc` | Printer/file share workflow testing |
| `remote assistance` / `offer remote` / `solicited remote` | RMM replaces RA in managed SMBs |
| `telemetry` / `cortana` / `input personalization` / `location` | Privacy; communicate change to users |
| `defender` / `scanning` / `monitoring` / `realtime` / `maps` | Third-party AV caveat |
| `smartscreen` | DNS filter equivalent caveat |
| `auto update` / `allow auto update` | Use Intune Update Ring instead |
| `app store` / `apps from the microsoft app store` | Pin version only if LOB compatibility required |
| `allow networking` | Required for Autopilot/cloud-join |
| `indexing encrypted` | Search index exposure risk |
| `search to use location` | Privacy; no business function lost |
| `uac restrictions` + `local accounts` | Pass-the-hash prevention |
| `block all consumer microsoft` / `consumer microsoft account` | M365 data governance |
| `block non admin` / `non-admin user install` | Malware install prevention |
| `universal windows apps` / `windows runtime api` | Web-based exploit vector |
| `block user from showing account details` | Username enumeration; no UX impact |
| `continue experiences` | Consumer feature; data exposure |
| `spotlight` | Lock screen telemetry; privacy |
| `ink workspace` / `game dvr` / `widget` | Consumer features; low business value |
| `clipboard` / `rdp` / `remote desktop` | RDS/VDI copy-paste trade-off |

### L2-only justification categories (added on top of L1 set)

| Pattern | Justification theme |
|---|---|
| `powershell` + `transcription` | Disk I/O / credential exposure in transcript logs |
| `powershell` + `script block` / `block logging` | Critical detection capability; skip only if EDR covers it |
| `powershell` (generic) | Strongly recommended for visibility |
| `mss` / `tcp` / `keepalive` / `dial` / `retransmission` / `routerdiscovery` | MSS legacy registry settings — low-risk hardening tweaks |
| `remote desktop` / `rdp` — time limit / disconnected / idle | Session timeout tuning for long-running tasks |
| `remote desktop` — allow users to connect | High attack surface; use RMM instead |
| `remote shell` | Disable; use RMM or Azure Arc |
| `com port` / `lpt port` / `plug and play` | Device redirection in RDP — block unless LOB requires it |
| `onedrive` / `one drive` | Business vs personal OneDrive sync distinction |
| `store originated` / `store application` / `access to the store` / `push to install` | Managed Store restriction |
| `advertising id` | Privacy control, no business impact |
| `watson` / `msdt` / `customer experience` / `error reporting` | Diagnostic telemetry — disable for privacy obligations |
| `cloud search` / `search highlights` | Cloud search data privacy |
| `camera` | Teams/Zoom dependency; use per-app permissions instead of device block |
| `cross device clipboard` / `shared user app data` / `message sync` | Data exfiltration risk from consumer cross-device features |
| `upload user activities` | Timeline privacy control |
| `font provider` | Online font fetch — low-risk to block |
| `online tips` | Settings app online content — low-risk to block |
| `device authentication` + `certificate` | PKI/SCEP prerequisite warning |
| `kms` / `avs validation` | Licensing compliance vs air-gap trade-off |
| `enterprise auth proxy` | Low-risk for SMBs without on-prem proxy |
| `connect now` / `wireless settings` | Wi-Fi credential exposure via WCN |
| `printer` + `driver` | Pre-stage drivers via Intune; block user installs |
| `printing over http` | Legacy protocol — safe to disable |
| `order prints` / `publish to web` / `internet connection wizard` / `registration` | Consumer features; no business impact |
| `messenger` + `customer experience` | Legacy telemetry |
| `search companion` / `help experience` | Consumer telemetry features |
| `mapper io` / `lltdio` / `rspndr` / `responder` | LLTD network topology drivers — rarely needed in managed SMBs |
| `convert warn to block` / `file hash` | Defender detection enhancement |
| `join microsoft maps` | MAPS telemetry — enable if Defender is primary AV |
| `remote encryption` | Ransomware detection — enable; pilot first |
| `log on as batch job` / `batch job` | Scope service accounts tightly |
| `user input methods` / `input methods to the system` | Low-risk privacy control |

### BL-only justification categories

| Pattern | Justification theme |
|---|---|
| `require device encryption` | Foundational; only exception is hardware incompatibility (no TPM) |
| `allow warning for other disk encryption` + `standard user` | Silent deployment / standard-user encryption flow |
| `allow warning for other disk encryption` | Silent deployment; confirm no third-party encryption in use |
| `cipher strength` / `encryption method` + `removable` | XTS-AES incompatible with non-Windows readers; AES-CBC fallback |
| `cipher strength` / `encryption method` + `operating system` | XTS-AES 256-bit; no valid reason to downgrade |
| `cipher strength` / `encryption method` (generic) | XTS-AES 128-bit for fixed drives; document deviation |
| `operating system drives can be recovered` + `recovery key` / `256-bit` | Azure AD escrow is preferred path; limit user-visible key display |
| `operating system drives can be recovered` + `recovery password` | 48-digit fallback; rely on IT portal retrieval |
| `operating system drives can be recovered` + `data recovery agent` | DRA not applicable in pure Azure AD / Intune environments |
| `operating system drives can be recovered` + `omit recovery options` / `wizard` | IT should control wizard visibility; escrow first |
| `operating system drives can be recovered` (generic) | Ensure Azure AD escrow active; test recovery before deploying |
| `fixed` + `recovered` + `recovery key` | Azure AD escrow preferred; disable user-visible key display |
| `fixed` + `recovered` + `recovery password` | 48-digit fallback; disable user-printable display |
| `fixed` + `recovered` + `data recovery agent` | DRA not applicable in pure cloud environments |
| `fixed` + `recovered` + `omit recovery options` / `wizard` | IT controls wizard; confirm escrow is active |
| `fixed` + `recovered` + `ad ds` / `active directory` / `storage of bitlocker` | AD DS escrow is for hybrid/on-prem; Azure AD used in pure cloud |
| `fixed` + `recovered` (generic) | Confirm Azure AD escrow; pilot before broad rollout |
| `require additional authentication` + `tpm startup pin` (no key) | Highest assurance but boot friction; TPM+PIN for workstations, TPM-only for kiosks |
| `require additional authentication` + `tpm startup key and pin` | Most restrictive (USB required at boot); only for high-security environments |
| `require additional authentication` + `tpm startup key` | Physical USB second factor; high overhead; TPM-only more practical |
| `require additional authentication` + `configure tpm startup` | TPM-only transparent encryption; add PIN for high-risk populations |
| `require additional authentication` (generic) | TPM-only baseline for SMBs; add PIN/key for high-risk device classes |
| `enforce drive encryption type` / `encryption type` | Full vs used-space-only; prefer full for re-provisioned devices |
| `deny write access to removable drives` | Strong DLP control; communicate and provide encrypted USB for approved use |
| `device enumeration policy` | Blocks DMA hardware attacks; may block docking stations — test first |
| `prevent installation of devices` / `device setup class` | Block rogue USB storage; build allow-list of approved device classes first |
| `bitlocker` / `encryption` / `recovery` (generic fallback) | Foundational; deviation requires documented exception; verify Azure AD escrow |

### Edge L1 (CISv3) justification categories

| Pattern | Justification theme |
|---|---|
| `smartscreen` | Equivalent DNS filter / web proxy caveat |
| `download restriction` | Malware risk; CIS-balanced value is recommended |
| `prevent bypassing` | No valid reason to allow SmartScreen bypass |
| `site isolation` | Memory overhead only trade-off (Spectre/Meltdown mitigation) |
| `legacy extension point` | DLL-injection attack vector; require modern alternative from vendor |
| `audio sandbox` | Audio codec exploit mitigation; only disable for documented driver incompatibility |
| `remote debugging` | Significant attack surface; always disable in production |
| `autofill` + `payment` | Payment card data storage exposure |
| `autofill` (generic) | Address data privacy; low operational impact |
| `saving passwords` / `save` + `password` | Force to centrally managed password manager |
| `import` + `data from other browsers` | Prevent personal browser data leaking into managed profile |
| `import` (generic) | Block credential/settings bleed-over from unmanaged browsers |
| `synchronization` / `sync` | Data governance — prevent history/passwords/favourites leaving device |
| `clear browsing` / `clear cached` / `clear history` / `disable saving browser history` | Residual data on shared/unattended devices |
| `inprivate` | Prevents circumventing history and web filter policies |
| `extension` | Block unmanaged add-ons; use allowlist instead |
| `payment methods` | Fingerprinting and payment data exposure via Payment Request API |
| `cast` | Chromecast; low security risk either way |
| `user feedback` / `in-app support` | Telemetry via feedback channel |
| `intrusive ads` / `ads setting` | Low-risk block; use per-site exception if needed |
| `cross-origin` + `auth` | Credential phishing via cross-origin resources |
| `basic authentication` + `http` | Cleartext credential transmission; migrate app to HTTPS first |
| `browser network time` | Certificate validation accuracy; block only under strict egress filtering |
| `dns interception` | Captive portal detection; disable only for false-positive appliances |
| `navigation errors` | URL suggestion privacy control; negligible UX impact |
| `insecure content` | Mixed HTTP/HTTPS TLS integrity; per-site exception preferred |
| `insecure forms` | HTTP form submission warning; disable only for legacy internal forms |
| `command-line flags` / `security warnings` + `command` | Unsafe flag exploit path; no valid managed reason to disable |
| `profile creation` | Prevent personal account adding to managed Edge profile |
| `ephemeral profiles` | Wipes managed settings on close; kiosk/shared-device use only |
| `linked account` | Keep corporate and personal identities separate |
| `startup boost` | Background process concern on low-spec devices; security-neutral |
| `background apps` | PWA background activity; disable if unexpected resource usage |
| `tab organization` | AI tab suggestions send page content to Microsoft |
| `search bar` | Sidebar search reduces ambient data collection |
| `bing` / `copilot` / `discover` | AI/Copilot integration sends page content; apply in data-classified envs |
| `compose` / `dall-e` | AI writing/image generation submits content to Microsoft AI |
| `shopping` / `rewards` / `wallet` / `crypto` / `donation` | Consumer features; no business impact |
| `follow service` / `3p serp` / `guided switch` / `standalone sidebar` | Consumer engagement features; telemetry reduction |
| `internet explorer mode` / `ie mode` / `reload in internet explorer` | Discourage legacy IE rendering; enable only for pending app modernisation |
| `unsupported os` | Suppressing warning hides security signal; only deviate if OS upgrade delayed |
| `update policy` / `component update` / `set the time period for update` | Align with patch management cadence |
| `delete old browser data` | Stale personal data removal; skip only during phased migration |
| `hsts` | HSTS bypass name list should be empty; per-host exception only |
| `webrtc` | Internal IP leakage via video calls; DisableNonProxiedUdp recommended |
| `upload` + `mobile` | Consumer cross-device feature; use SharePoint/OneDrive instead |
| `feature flags` | Prevent users from bypassing managed Edge configuration |
| `share experience` | Reduce data sharing via consumer share targets |
| `related matches` / `find on page` | AI fuzzy search sends page content to Microsoft |
| `typo protection` | Low-friction phishing-site warning; disable only for internal hostname false positives |
| `first-run` / `first run` / `splash screen` | Suppress personal account/import prompts on managed deployment |
| `globally scoped` + `auth` | Credential reuse risk across sites via shared HTTP auth cache |
| `disk cache size` | Disk usage cap (250 MB CIS recommended); adjust for power users |
| `enterprise hardware platform` | Scope to allowlisted extensions only |
| `e-tree` / `etree` | Consumer donation feature; no business impact |

> **Edge fallback prefix strip:** regex `^cisv3\s*-\s*edge\s*-\s*l1\s*-\s*` (case-insensitive).
> Fallback text variants:
> - **Simple:** `'<policy name>' is a low-complexity, single-value setting...`
> - **Moderate:** `'<policy name>' has moderate implementation risk... pilot on a test group before broad rollout.`
> - **Complex:** `'<policy name>' is a complex Edge policy with potential dependencies on other browser features or web apps... Use Edge policy reporting to validate impact before enforcement.`

### Fallback (no specific match)
Uses name-aware text based on complexity tier:
- **Simple:** `'<policy name>' is a low-complexity, single-value setting...`
- **Moderate:** `'<policy name>' has moderate implementation risk...`
- **Complex:** `'<policy name>' is a complex policy with potential dependencies...`

The CIS prefix is stripped from the name before inserting into fallback text:
- L1/L2: `cisv4 - win - lN - `
- BL (new): matched via regex `^cisv?4\s*-\s*ifw\s*-\s*bl\s*-\s*` (handles both `CIS4v` and `CISv4` typos in filenames)
- BL (old): plain string strip `"cisv4 - win - bl - "` (no regex)
- Edge L1: regex `^cisv3\s*-\s*edge\s*-\s*l1\s*-\s*` (case-insensitive)

---

## How to run

```bash
# Sample (20 rows) — default for all scripts except Edge
python "CIS Microsoft Intune for Windows Level N/generate_summary_csv.py"

# Full run — edit SAMPLE_MODE = False in the script first (not needed for Edge)
python "CIS Microsoft Intune for Windows Level N/generate_summary_csv.py"

# Edge L1 — defaults to SAMPLE_MODE = False (full run)
python "CISv3 Microsoft Edge Level 1 Benchmark/generate_summary_csv.py"
```

Output goes to the `Summary CSV\` subfolder within each benchmark folder.

---

## Spreadsheet formatter (`format_spreadsheet.py`)

Converts the CSV to a formatted `.xlsx`. Run from the repo root:

```bash
python format_spreadsheet.py
```

### Colour palette

| Element | Hex |
|---|---|
| Header background | `#1F3864` (dark navy) |
| Header text | `#FFFFFF` |
| Even row background | `#EEF3FA` (light blue-grey) |
| Odd row background | `#FFFFFF` |
| Cell border | `#BFC9D6` (muted blue-grey) |

### Complexity badge colours

| Value | Background | Text |
|---|---|---|
| Simple | `#C6EFCE` | `#276221` (dark green) |
| Moderate | `#FFEB9C` | `#9C6500` (dark amber) |
| Complex | `#FFC7CE` | `#9C0006` (dark red) |

### Column widths

| Col | Header | Width |
|---|---|---|
| 1 | Name | 55 |
| 2 | Description | 70 |
| 3 | Recommended Setting | 40 |
| 4 | Complexity | 13 |
| 5 | SMB Justification | 65 |

### Features
- Frozen header row (`freeze_panes = "A2"`)
- Auto-filter dropdowns on all headers
- Alternating row shading
- Text wrap; vertical alignment: top
- Row heights: header 28pt, data 60pt
- Font: Segoe UI 10pt (headers) / 9pt (data)
- Thin border on all cells
- Sheet tab colour: `#1F3864`

### Adapting for a new level
1. Update `INPUT_CSV` and `OUTPUT_XLS` at the top of the script.
2. Adjust `COL_WIDTHS` if column count/content changes.
3. If the colour-coded column moves, update the `col_idx == 4` check.
4. Change `ws.title` to an appropriate sheet name.

---

## Applying to a new CIS level folder

Checklist when adding a new level (e.g., Level 3, Edge, macOS):

1. **Copy** `generate_summary_csv.py` from the nearest existing level.
2. **Update** `LEVEL_TAG` / output prefix (e.g., `CIS_L3_Policy_Summary_`).
3. **Update** `SOURCE_DIRS` — list all JSON source folders for that level.
4. **Update** fallback prefix strip regex (e.g., `cisv4 - win - l3 - `).
5. **Review** complexity keywords — add any new technology areas present in that level.
6. **Review** SMB justification patterns — add new categories for new policy domains.
7. **Update** `_USER_RIGHTS_KEYWORDS` if the level introduces new user-rights policies.
8. **Run sample mode** and spot-check Column C for any N/A rows or mis-labelled inferences.
9. **Update this master CONTEXT_SUMMARY.md** with the new level's details.

---

## Known edge cases (shared)

| Issue | Affected level(s) | Notes |
|---|---|---|
| Rename account policies return empty string as `(configured value)` | L1 | Override to `Apply rename (see policy)` for clarity |
| `Allow Auto Update` maps `_2` to generic `Option 2` | L1 | Actual meaning: "Notify for download and install"; expand `_PAYLOAD_VALUE_MAP` |
| Duplicate WinRM Client vs Service justifications | L1 | Split match if differentiated risk profiles needed |
| `camera` block conflicts with Teams/Zoom | L2 | Current justification flags this; consider per-app exception note |
| `mss` TCP policies surface raw integer as `X (configured value)` | L2 | Add name-based override for human-readable labels |
| `Join Microsoft MAPS` maps `_2` to `Option 2` | L2 | Expand `_PAYLOAD_VALUE_MAP` with MAPS-specific entry if cleaner label needed |
| `Remote Encryption Protection Aggressiveness` returns numeric level | L2 | Add override mapping level number to descriptive label |
| `"...can be recovered is set to Enabled"` (parent enable policies) classified as Moderate | BL (new) | Fixed: added `"recovered"` to COMPLEX_KEYWORDS; distinct from `"recovery"` substring |
| `"Require additional authentication at  startup"` (parent policy) not matched by full-phrase keyword | BL (new) | Fixed: double space in JSON name field breaks exact-phrase match; use shortened keyword `"require additional authentication"` |
| One JSON filename uses `CIS4v` prefix instead of `CISv4` | BL (new) | Cosmetic only — name field inside JSON is correct `CISv4`; prefix-strip regex handles both forms |
| All 16 BL policies resolve to Complex (0 Simple, 0 Moderate) | BL (new) | Expected: all policies are TPM/recovery-related; no simpler operational settings in this benchmark set |
| BL descriptions are all empty strings | BL (new) | Column B will be blank for all rows; Column C falls through to payload inference (Stage 2) |
| Older BL folder lacks `"recovered"` / `"require additional authentication"` keywords | BL (old) | Script was written before those keywords were identified as needed; newer BL script has the fixes |
| Edge script has no `_USER_RIGHTS_KEYWORDS` / no name-based Stage 3 override | Edge L1 | Edge policies don't include Windows user-rights assignments; `extract_recommended` goes directly from payload inference to N/A |
| Edge `_PAYLOAD_VALUE_MAP` has no WinRM full-token entries | Edge L1 | WinRM-specific tokens not present in Edge policy JSON; map is trimmed accordingly |
| Edge `assess_complexity` omits `description` parameter | Edge L1 | Intentional — complexity is keyed on name only; description prose caused false positives |
| `save` + `password` pattern in `smb_justification` has ambiguous `and` precedence | Edge L1 | Python evaluates as `"save" in name_lower and ("password" in name_lower)` due to operator precedence; effectively matches both substrings anywhere in name |
