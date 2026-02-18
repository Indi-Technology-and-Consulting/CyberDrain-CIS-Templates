"""
Merge script for Intune policies where each file is a standalone, independent
choiceSettingInstance (no shared parent, no children). Each file contributes one
entry to the merged policy's `settings` array.

Example: Account Logon / Account Logon Logoff audit policy settings.

Usage:
  1. Update CONFIGURATION section below
  2. Run from the directory containing the source JSON files:
       py merge_multipleSettings.py
  3. Move output to Merged Policies/ and originals to Unmerged Policies/
"""
import json
import glob
import uuid
import copy

# === CONFIGURATION - Adjust these for each merge ===
file_pattern = "CISv4 - WIN - L1 - Network access*.json"
output_name = "CISv4 - WIN - L1 - Network Access: All Settings"
output_description = "CIS Benchmark v4 - All Network Access settings consolidated into a single policy."
output_filename = "CISv4 - WIN - L1 - Network Access All Settings.json"
# ====================================================

def deep_replace_id(obj, old, new):
    if isinstance(obj, str):
        return obj.replace(old, new)
    elif isinstance(obj, dict):
        return {deep_replace_id(k, old, new): deep_replace_id(v, old, new) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [deep_replace_id(item, old, new) for item in obj]
    return obj

# Find all matching files
source_files = sorted(glob.glob(file_pattern))
print(f"Found {len(source_files)} files to merge")
for f in source_files:
    print(f"  {f}")

# Read all files and extract the settings entry from each
all_settings = []
for f in source_files:
    with open(f, 'r', encoding='utf-16') as fh:
        data = json.load(fh)
    setting = copy.deepcopy(data['settings'][0])
    sid = setting['settingInstance']['settingDefinitionId']
    all_settings.append(setting)
    print(f"  Extracted setting '{sid}' from: {f}")

# Use the first file as the template for top-level policy metadata
with open(source_files[0], 'r', encoding='utf-16') as fh:
    template = json.load(fh)

new_id = str(uuid.uuid4())
old_id = template['id']

merged = deep_replace_id(template, old_id, new_id)

# Update policy metadata
merged['name'] = output_name
merged['description'] = output_description
merged['settingCount'] = len(all_settings)

# Replace the settings array: one entry per source file, renumbered by index
numbered_settings = []
for idx, setting in enumerate(all_settings):
    s = copy.deepcopy(setting)
    # Update the setting id and any odata references to use the new policy id and index
    s['id'] = str(idx)
    s = deep_replace_id(s, old_id, new_id)
    # Fix per-setting odata links to use the correct index
    old_setting_id = source_files[idx] # placeholder; we re-key by index
    if '@odata.id' in s:
        # Rebuild to correct index: replace trailing index reference
        import re
        s['@odata.id'] = re.sub(
            r"settings\(%270%27\)|settings\('0'\)",
            f"settings('{idx}')",
            s['@odata.id']
        )
    if '@odata.editLink' in s:
        s['@odata.editLink'] = re.sub(
            r"settings\(%270%27\)|settings\('0'\)",
            f"settings('{idx}')",
            s['@odata.editLink']
        )
    numbered_settings.append(s)

merged['settings'] = numbered_settings

# Write output as UTF-8
with open(output_filename, 'w', encoding='utf-8') as fh:
    json.dump(merged, fh, indent=4, ensure_ascii=False)

print(f"\nMerged {len(all_settings)} settings into: {output_filename}")
print("\nMerged settings:")
for s in all_settings:
    si = s['settingInstance']
    sid = si['settingDefinitionId']
    if 'choiceSettingValue' in si:
        val = si['choiceSettingValue']['value']
    elif 'simpleSettingValue' in si:
        val = si['simpleSettingValue']['value']
    else:
        val = '(unknown type)'
    print(f"  {sid}: {val}")
