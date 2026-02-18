"""
Merge script for Intune policies that use groupSettingCollectionValue structure.
Example: ASR (Attack Surface Reduction) rules.

Each source file has ONE rule in groupSettingCollectionValue[0].children[0].
The merge combines all rules into a single groupSettingCollectionValue array.

Usage:
  1. Update CONFIGURATION section below
  2. Run from the directory containing the source JSON files:
       py merge_groupSettingCollection.py
  3. Move output to Merged Policies/ and originals to Unmerged Policies/
"""
import json
import glob
import uuid
import os
import copy

# === CONFIGURATION - Adjust these for each merge ===
file_pattern = "CISv4 - WIN - L1 - ASR *.json"  # Glob pattern for source files
output_name = "CISv4 - WIN - L1 - ASR: All Rules"  # Name for merged policy
output_description = "CIS Benchmark v4 - All Attack Surface Reduction (ASR) rules consolidated into a single policy."
output_filename = "CISv4 - WIN - L1 - ASR All Rules.json"
# ====================================================

# Find all matching files
asr_files = sorted(glob.glob(file_pattern))
print(f"Found {len(asr_files)} files to merge")

# Extract the child setting (the actual rule) from each file
all_children = []
for f in asr_files:
    # Source files are UTF-16 encoded (Microsoft export format)
    with open(f, 'r', encoding='utf-16') as fh:
        data = json.load(fh)
    child = data['settings'][0]['settingInstance']['groupSettingCollectionValue'][0]['children'][0]
    all_children.append(child)
    print(f"  Extracted rule from: {f}")

# Use the first file as a template for the merged policy
with open(asr_files[0], 'r', encoding='utf-16') as fh:
    template = json.load(fh)

# Generate a new unique ID for the merged policy
new_id = str(uuid.uuid4())
old_id = template['id']

# Deep-replace all references to the old policy ID with the new one
def deep_replace_id(obj, old, new):
    if isinstance(obj, str):
        return obj.replace(old, new)
    elif isinstance(obj, dict):
        return {deep_replace_id(k, old, new): deep_replace_id(v, old, new) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [deep_replace_id(item, old, new) for item in obj]
    return obj

merged = deep_replace_id(template, old_id, new_id)

# Update policy metadata
merged['name'] = output_name
merged['description'] = output_description
merged['settingCount'] = len(all_children)

# Build the merged groupSettingCollectionValue array
# Each rule becomes its own entry in the collection
group_values = []
for child in all_children:
    group_values.append({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingValue",
        "settingValueTemplateReference": None,
        "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
        "children": [child]
    })

merged['settings'][0]['settingInstance']['groupSettingCollectionValue'] = group_values

# Write the merged file as UTF-8 JSON (standard format)
with open(output_filename, 'w', encoding='utf-8') as fh:
    json.dump(merged, fh, indent=4, ensure_ascii=False)

print(f"\nMerged {len(all_children)} rules into: {output_filename}")
