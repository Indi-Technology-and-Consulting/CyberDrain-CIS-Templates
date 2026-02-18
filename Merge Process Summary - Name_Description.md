# Intune Policy JSON Merge Process

## Overview

This document describes how to merge multiple individual Microsoft Intune Configuration Policy JSON files (exported from Microsoft Graph API) into a single consolidated policy JSON file.

Three merge patterns exist depending on the JSON structure of the source policies:

| Structure | Script | Use When |
|-----------|--------|----------|
| `groupSettingCollectionValue` | `merge_groupSettingCollection.py` | Each file adds one entry to a collection (e.g., ASR rules) |
| `choiceSettingValue.children` | `merge_choiceSettingChildren.py` | Each file configures one child of a shared parent setting (e.g., Device Password Enabled) |
| Independent `choiceSettingInstance` (no shared parent) | `merge_multipleSettings.py` | Each file is a standalone setting; merged into one policy with multiple `settings` array entries (e.g., audit policy categories) |

## Prerequisites

- Python 3.x installed (on Windows, use `py` command)
- All source JSON files must be Intune policy exports from the Microsoft Graph API beta endpoint
- All source files must share the same parent `settingDefinitionId` (i.e., they are the same type of policy with different individual settings)

## Source File Structure

Each exported Intune policy JSON file is:
- **Encoded as UTF-16** (Microsoft export format)
- A `deviceManagementConfigurationPolicy` object from the Graph API
- Contains a `settings` array with one entry
- That entry has a `settingInstance` whose structure determines which merge script to use

### Structure A: groupSettingCollectionValue (e.g., ASR Rules)

Each file has ONE rule/entry. The merge combines them into one collection.

```
root
├── name, id, description, settingCount, platforms, technologies...
└── settings[0]
    └── settingInstance
        ├── settingDefinitionId  (e.g., "..._attacksurfacereductionrules")
        └── groupSettingCollectionValue[]
            └── [0]
                └── children[]
                    └── [0]
                        ├── settingDefinitionId  (the specific rule ID)
                        └── choiceSettingValue
                            └── value  (e.g., "..._block" or "..._audit")
```

### Structure B: choiceSettingValue.children (e.g., Device Password Enabled)

Each file has ALL children but only one with its CIS-recommended value. The merge takes the correct value for each child from its owning file.

```
root
├── name, id, description, settingCount, platforms, technologies...
└── settings[0]
    └── settingInstance
        ├── settingDefinitionId  (e.g., "..._devicepasswordenabled")
        └── choiceSettingValue
            ├── value  (e.g., "..._devicepasswordenabled_0")
            └── children[]
                ├── [0] choiceSettingInstance  (e.g., allowsimpledevicepassword)
                ├── [1] choiceSettingInstance  (e.g., alphanumericdevicepasswordrequired)
                ├── [2] simpleSettingInstance  (e.g., devicepasswordexpiration)
                └── ...
```

### Structure C: Independent choiceSettingInstance (e.g., Audit Policy Categories)

Each file configures a completely independent setting with its own `settingDefinitionId` and no children. The merge collects all settings into a single policy with multiple entries in the `settings` array, one per source file.

```
root
├── name, id, description, settingCount, platforms, technologies...
└── settings[]
    ├── [0]
    │   └── settingInstance
    │       ├── settingDefinitionId  (e.g., "..._auditcredentialvalidation")
    │       └── choiceSettingValue
    │           ├── value  (e.g., "..._3")
    │           └── children[]  (empty)
    ├── [1]
    │   └── settingInstance
    │       ├── settingDefinitionId  (e.g., "..._auditaccountlockout")
    │       └── choiceSettingValue
    │           ├── value  (e.g., "..._2")
    │           └── children[]  (empty)
    └── ...
```

## Merge Process (Step-by-Step)

### Step 1: Identify Files to Merge

Find all JSON files that belong to the same policy group. They should share:
- The same `settingDefinitionId` in `settings[0].settingInstance`
- The same `platforms` and `technologies` values

### Step 2: Determine the Structure Type

Open one of the source files and check `settings[0].settingInstance`:
- If it contains `groupSettingCollectionValue` → use **`merge_groupSettingCollection.py`**
- If it contains `choiceSettingValue` with a `children` array → use **`merge_choiceSettingChildren.py`**
- If it contains `choiceSettingValue` with an **empty** `children` array and the files each have a **different** `settingDefinitionId` → use **`merge_multipleSettings.py`**

### Step 3: Configure and Run the Script

Each script has a `CONFIGURATION` section at the top. Update:
- `file_pattern` - glob pattern for source files
- `output_name` - display name for the merged policy
- `output_description` - description for the merged policy
- `output_filename` - output file name

For `merge_multipleSettings.py`, the configuration is the same as `merge_groupSettingCollection.py` (no `base_filename` or `file_to_setting` needed).

For `merge_choiceSettingChildren.py`, also update:
- `base_filename` - the parent/base policy file (the one without a setting-specific suffix)
- `file_to_setting` - a mapping from filename keywords to the child `settingDefinitionId` each file owns

Run from the directory containing the source files:
```
py merge_groupSettingCollection.py
# or
py merge_choiceSettingChildren.py
```

### Step 4: Organize Files

After merging:

1. **Move the merged output file** to the `Merged Policies` subfolder
2. **Move the original individual files** to the `Unmerged Policies` subfolder

This preserves the originals for reference while keeping the working directory clean.

## Important Notes

1. **Encoding**: Source files are UTF-16 (Microsoft export). The merged output is written as UTF-8 for better compatibility. Both formats import correctly into Intune.

2. **ID Replacement**: The merged policy gets a new UUID. All `@odata.id`, `@odata.editLink`, and other OData references containing the old policy ID are updated throughout the JSON via deep replacement.

3. **Setting Actions Preserved**: Each rule's original action (Block, Audit, etc.) from the source file is preserved exactly as-is in the merged output.

4. **settingCount**: Updated to reflect the total number of rules in the merged policy.

5. **Merge Structure**: Each individual rule becomes a separate entry in the `groupSettingCollectionValue` array. The parent `settingDefinitionId` stays the same since all rules share it.

## Completed Merges

### ASR Rules (groupSettingCollectionValue)

Script: `merge_groupSettingCollection.py`
Output: `Merged Policies/CISv4 - WIN - L1 - ASR All Rules.json`

| Rule | Action |
|------|--------|
| Block abuse of exploited vulnerable signed drivers | Block |
| Block Adobe Reader from creating child processes | Block |
| Block all Office applications from creating child processes | Audit |
| Block credential stealing from Windows LSASS | Block |
| Block executable content from email client and webmail | Block |
| Block executable files unless they meet prevalence/age/trusted list | Audit |
| Block execution of potentially obfuscated scripts | Audit |
| Block JavaScript or VBScript from launching downloaded executable content | Block |
| Block Office applications from injecting code into other processes | Block |
| Block Office communication application from creating child processes | Audit |
| Block persistence through WMI event subscription | Block |
| Block process creations originating from PSExec and WMI commands | Audit |
| Block untrusted and unsigned processes that run from USB | Block |
| Block Win32 API calls from Office macros | Block |
| Use advanced protection against ransomware | Audit |

### Network Access (Independent choiceSettingInstance)

Script: `merge_multipleSettings.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Network Access All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| Do not allow anonymous enumeration of SAM accounts | Enabled (_1) |
| Do not allow anonymous enumeration of SAM accounts and shares | Enabled (_1) |
| Restrict anonymous access to Named Pipes and Shares | Enabled (_1) |
| Restrict clients allowed to make remote calls to SAM | `Administrators: Remote Access: Allow.` |

### Network Security (Independent choiceSettingInstance)

Script: `merge_multipleSettings.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Network Security All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| Allow PKU2U authentication requests | Disabled (_1) |
| Allow Local System to use computer identity for NTLM | Enabled (_1) |
| Do not store LAN Manager hash on next password change | Enabled (_1) |
| LAN Manager authentication level | NTLMv2 only, refuse LM & NTLM (_5) |
| Minimum session security for NTLMSSP clients | Require NTLMv2 + 128-bit encryption (_537395200) |
| Minimum session security for NTLMSSP servers | Require NTLMv2 + 128-bit encryption (_537395200) |
| Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts (_2) |

### User Account Control (Independent choiceSettingInstance)

Script: `merge_multipleSettings.py`
Output: `Merged Policies/CISv4 - WIN - L1 - User Account Control All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| Behavior of elevation prompt for administrators | Prompt for credentials on secure desktop (_2) |
| Behavior of elevation prompt for standard users | Automatically deny elevation requests (_0) |
| Detect application installations and prompt for elevation | Enabled (_1) |
| Only elevate UIAccess apps installed in secure locations | Enabled (_1) |
| Run all administrators in Admin Approval Mode | Enabled (_1) |
| Switch to secure desktop when prompting for elevation | Enabled (_1) |
| Use Admin Approval Mode | Enabled (_1) |

### Specify Maximum Log File Size (Independent choiceSettingInstance)

Script: `merge_multipleSettings.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Specify Maximum Log File Size All Channels.json`

| Setting | CIS Value (KB) |
|---------|----------------|
| Application log max size | 32768 |
| Security log max size | 196608 |
| Setup log max size (`channel_logmaxsize_3`) | 32768 |
| System log max size | 32768 |

### Control Event Log Behavior (Independent choiceSettingInstance)

Script: `merge_multipleSettings.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Control Event Log Behavior All Channels.json`

| Setting | CIS Value |
|---------|-----------|
| Control Event Log Behavior - Application | Disabled (_0) |
| Control Event Log Behavior - Security (`channel_log_retention_2`) | Disabled (_0) |
| Control Event Log Behavior - Setup (`channel_log_retention_3`) | Disabled (_0) |
| Control Event Log Behavior - System (`channel_log_retention_4`) | Disabled (_0) |

### Account Logon Audit Settings (Independent choiceSettingInstance)

Script: `merge_multipleSettings.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Account Logon All Audit Settings.json`

| Setting | CIS Value |
|---------|-----------|
| Audit Credential Validation | Success and Failure (_3) |
| Audit Account Lockout | Failure (_2) |
| Audit Group Membership | Success (_1) |
| Audit Logoff | Success (_1) |
| Audit Logon | Success and Failure (_3) |

### Enable Domain Network Firewall (choiceSettingValue.children)

Script: `merge_choiceSettingChildren.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Enable Domain Network Firewall All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| EnableFirewall | True (parent) |
| DefaultInboundAction | Allow (_0) |
| DisableInboundNotifications | True |
| EnableLogDroppedPackets | True |
| EnableLogSuccessConnections | True |
| LogFilePath | `%systemroot%\system32\LogFiles\Firewall\pfirewall.log` |
| LogMaxFileSize | 16384 |

### Enable Public Network Firewall (choiceSettingValue.children)

Script: `merge_choiceSettingChildren.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Enable Public Network Firewall All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| EnableFirewall | True (parent) |
| AllowLocalIpsecPolicyMerge | False |
| AllowLocalPolicyMerge | False |
| DefaultInboundAction | Block (_1) |
| DisableInboundNotifications | True |
| EnableLogDroppedPackets | True |
| EnableLogSuccessConnections | True |
| LogFilePath | `%systemroot%\system32\LogFiles\Firewall\pfirewall.log` |
| LogMaxFileSize | 16384 |

### Enable Private Network Firewall (choiceSettingValue.children)

Script: `merge_choiceSettingChildren.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Enable Private Network Firewall All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| EnableFirewall | True (parent) |
| DefaultInboundAction | Block (_1) |
| DisableInboundNotifications | True |
| EnableLogDroppedPackets | True |
| EnableLogSuccessConnections | True |
| LogFilePath | `%systemroot%\system32\LogFiles\Firewall\pfirewall.log` |
| LogMaxFileSize | 16384 |

### Device Password Enabled (choiceSettingValue.children)

Script: `merge_choiceSettingChildren.py`
Output: `Merged Policies/CISv4 - WIN - L1 - Device Password Enabled All Settings.json`

| Setting | CIS Value |
|---------|-----------|
| AllowSimpleDevicePassword | Block (_1) |
| AlphanumericDevicePasswordRequired | Password or Alphanumeric PIN required (_0) |
| MinDevicePasswordComplexCharacters | Digits and lowercase letters (_2) |
| DevicePasswordExpiration | 365 |
| DevicePasswordHistory | 24 |
| MaxDevicePasswordFailedAttempts | 5 |
| MaxInactivityTimeDeviceLock | 15 |
| MinDevicePasswordLength | 14 |
