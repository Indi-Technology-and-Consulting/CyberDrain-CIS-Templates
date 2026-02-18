"""
Merge script for Intune policies that use choiceSettingValue.children structure.
Example: Device Password Enabled settings.

Each source file has the SAME set of children but only the file's named setting
has the CIS-recommended value (others are defaults). The merge takes the correct
value for each child from the file that specifically configures it.

Usage:
  1. Update CONFIGURATION section below (file_pattern, output_*, and file_to_setting map)
  2. Run from the directory containing the source JSON files:
       py merge_choiceSettingChildren.py
  3. Move output to Merged Policies/ and originals to Unmerged Policies/
"""
import json
import glob
import uuid
import os
import copy

# === CONFIGURATION - Adjust these for each merge ===
file_pattern = "CISv4 - WIN - L1 - Enable Domain Network Firewall*.json"
output_name = "CISv4 - WIN - L1 - Enable Domain Network Firewall: All Settings"
output_description = "CIS Benchmark v4 - All Enable Domain Network Firewall settings consolidated into a single policy."
output_filename = "CISv4 - WIN - L1 - Enable Domain Network Firewall All Settings.json"

# Base filename (the parent policy with defaults - no suffix after the common prefix)
base_filename = "CISv4 - WIN - L1 - Enable Domain Network Firewall.json"

# Map filename keywords -> child settingDefinitionId suffix they own.
# Use the text that appears AFTER the base name in the filename.
file_to_setting = {
    "Default  Inbound Action": "defaultinboundaction",
    "Disable  Inbound Notifications": "disableinboundnotifications",
    "Enable Log  Dropped Packets": "enablelogdroppedpackets",
    "Enable Log  Success Connections": "enablelogsuccessconnections",
    "Log File Path": "logfilepath",
    "Log Max File  Size": "logmaxfilesize",
}
# ====================================================

# Find all matching files
all_files = sorted(glob.glob(file_pattern))
print(f"Found {len(all_files)} files to merge")
for f in all_files:
    print(f"  {f}")

# Read all files
file_data = []
for f in all_files:
    with open(f, 'r', encoding='utf-16') as fh:
        data = json.load(fh)
    children = data['settings'][0]['settingInstance']['choiceSettingValue']['children']
    file_data.append((f, data, children))

# Find the base file
base_file = None
for f, data, children in file_data:
    if os.path.basename(f) == base_filename:
        base_file = (f, data, children)
        break

if not base_file:
    raise Exception(f"Base file not found: {base_filename}")

# Start with base file's children
base_children_by_id = {}
for child in base_file[2]:
    base_children_by_id[child['settingDefinitionId']] = copy.deepcopy(child)

# Override each child with the version from the file that owns it
for f, data, children in file_data:
    basename = os.path.basename(f)
    for keyword, target_sid in file_to_setting.items():
        if keyword in basename:
            for child in children:
                child_sid = child['settingDefinitionId']
                # Direct match: child's settingDefinitionId contains the target
                if target_sid in child_sid:
                    base_children_by_id[child_sid] = copy.deepcopy(child)
                    print(f"  Taking {child_sid} from: {basename}")
                    break
                # Nested match: target is a nested child (e.g. complexcharacters under alphanumeric)
                if 'choiceSettingValue' in child:
                    nested = child.get('choiceSettingValue', {}).get('children', [])
                    for nc in nested:
                        if target_sid in nc.get('settingDefinitionId', ''):
                            base_children_by_id[child_sid] = copy.deepcopy(child)
                            print(f"  Taking {child_sid} (with nested {target_sid}) from: {basename}")
                            break

# Build final children preserving order from the file with the most children
best_order_file = max(file_data, key=lambda x: len(x[2]))
final_children = []
seen_ids = set()
for child in best_order_file[2]:
    sid = child['settingDefinitionId']
    if sid in base_children_by_id and sid not in seen_ids:
        final_children.append(base_children_by_id[sid])
        seen_ids.add(sid)
for sid, child in base_children_by_id.items():
    if sid not in seen_ids:
        final_children.append(child)
        seen_ids.add(sid)

# Build merged policy from base template
merged = copy.deepcopy(base_file[1])
new_id = str(uuid.uuid4())
old_id = merged['id']

def deep_replace_id(obj, old, new):
    if isinstance(obj, str):
        return obj.replace(old, new)
    elif isinstance(obj, dict):
        return {deep_replace_id(k, old, new): deep_replace_id(v, old, new) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [deep_replace_id(item, old, new) for item in obj]
    return obj

merged = deep_replace_id(merged, old_id, new_id)
merged['name'] = output_name
merged['description'] = output_description
merged['settingCount'] = len(final_children)
merged['settings'][0]['settingInstance']['choiceSettingValue']['children'] = final_children

# Write output as UTF-8
with open(output_filename, 'w', encoding='utf-8') as fh:
    json.dump(merged, fh, indent=4, ensure_ascii=False)

print(f"\nMerged {len(final_children)} settings into: {output_filename}")
print("\nMerged settings:")
for child in final_children:
    sid = child['settingDefinitionId']
    if 'choiceSettingValue' in child:
        val = child['choiceSettingValue']['value']
        print(f"  {sid}: {val}")
    elif 'simpleSettingValue' in child:
        val = child['simpleSettingValue']['value']
        print(f"  {sid}: {val}")
