import json
import pandas as pd

# Load JSON
with open("nvdcve-1.1-2024.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Extract CVEs list
cve_items = data["CVE_Items"]

# Prepare list of records
records = []

for item in cve_items:
    try:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        severity = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", None)
        impact_score = item.get("impact", {}).get("baseMetricV3", {}).get("impactScore", None)
        attack_vector = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackVector", None)
        attack_complexity = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackComplexity", None)
        privileges_required = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("privilegesRequired", None)

        records.append({
            "CVE_ID": cve_id,
            "description": description,
            "severity": severity,
            "impact_score": impact_score,
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "privileges_required": privileges_required
        })
    except Exception as e:
        print(f"Skipping record due to error: {e}")
        continue

# Convert to DataFrame
df = pd.DataFrame(records)

# Save to CSV
df.to_csv("parsed_nvd_2024.csv", index=False)
print(f"✅ Parsed {len(df)} records and saved to parsed_nvd_2024.csv")
