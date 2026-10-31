import os
import json
import pandas as pd
from tabulate import tabulate

def load_json_configuration(file_path):
    """Safely reads structural JSON data configurations from disk."""
    if not os.path.exists(file_path):
        print(f"[-] Configuration file not found: {file_path}")
        return None
    with open(file_path, "r") as f:
        return json.load(f)

def execute_posture_audit(assets, rules):
    """Parses cloud infrastructure assets against defined compliance benchmarks."""
    compliance_violations = []
    policies = rules.get("policies", {})

    print("[*] Initiating Cloud Security Posture Compliance Audit Loop...")

    for asset in assets:
        asset_type = asset.get("asset_type")
        asset_id = asset.get("asset_id")
        asset_name = asset.get("asset_name")
        region = asset.get("region", "global")
        
        # --- 1. STORAGE POLICIES AUDIT ---
        if asset_type == "Storage_Bucket":
            spec = policies.get("STORAGE_ENFORCEMENT", {})
            if spec.get("fail_on_public") and asset.get("public_access"):
                compliance_violations.append({
                    "Asset_ID": asset_id, "Asset_Type": asset_type, "Asset_Name": asset_name,
                    "Policy_Violated": "CIS-Storage-01: Publicly Exposed Bucket",
                    "Severity": "CRITICAL", "Region": region
                })
            if spec.get("require_encryption") and not asset.get("encryption_enabled"):
                compliance_violations.append({
                    "Asset_ID": asset_id, "Asset_Type": asset_type, "Asset_Name": asset_name,
                    "Policy_Violated": "CIS-Storage-02: Missing At-Rest Encryption",
                    "Severity": "HIGH", "Region": region
                })

        # --- 2. NETWORK FIREWALL POLICIES AUDIT ---
        elif asset_type == "Security_Group":
            blocked_ports = policies.get("NETWORK_ENFORCEMENT", {}).get("blocked_ingress_ports", [])
            for rule in asset.get("open_ingress_rules", []):
                if "0.0.0.0/0" in rule:  # Open to the entire world
                    port = int(rule.split(":")[-1])
                    if port in blocked_ports:
                        compliance_violations.append({
                            "Asset_ID": asset_id, "Asset_Type": asset_type, "Asset_Name": asset_name,
                            "Policy_Violated": f"CIS-Network-04: Unrestricted Ingress Port {port} (SSH)",
                            "Severity": "CRITICAL", "Region": region
                        })

        # --- 3. IDENTITY & ACCESS POLICIES AUDIT ---
        elif asset_type == "IAM_User":
            spec = policies.get("IAM_ENFORCEMENT", {})
            if spec.get("require_mfa") and not asset.get("mfa_active"):
                compliance_violations.append({
                    "Asset_ID": asset_id, "Asset_Type": asset_type, "Asset_Name": asset_name,
                    "Policy_Violated": "CIS-IAM-01: User Missing Multi-Factor Authentication",
                    "Severity": "HIGH", "Region": region
                })
            if asset.get("api_key_age_days", 0) > spec.get("max_api_key_age_days", 90):
                compliance_violations.append({
                    "Asset_ID": asset_id, "Asset_Type": asset_type, "Asset_Name": asset_name,
                    "Policy_Violated": f"CIS-IAM-02: Stale API Access Key ({asset.get('api_key_age_days')} Days old)",
                    "Severity": "MEDIUM", "Region": region
                })

    return compliance_violations

def main():
    # Load raw configuration feeds
    assets = load_json_configuration("mock_cloud_infrastructure.json")
    rules = load_json_configuration("compliance_rules.json")

    if not assets or not rules:
        print("[-] Pipeline initialization failed due to missing source feeds.")
        return

    # Execute security validation logic
    violations = execute_posture_audit(assets, rules)
    
    # Process output metrics using pandas dataframes
    df = pd.DataFrame(violations)
    
    print("\n" + "="*80)
    print("CLOUD SECURITY POSTURE MANAGEMENT (CSPM) DRIFT REPORT")
    print("="*80)
    
    if not df.empty:
        # Display formatted log directly in console panel
        print(tabulate(df, headers='keys', tablefmt='psql', showindex=False))
        
        # Export structured matrix directly for our Tableau visualization layer
        output_csv = "cloud_compliance_drift_report.csv"
        df.to_csv(output_csv, index=False)
        print(f"\n[+] Compliance metrics successfully committed to portfolio feed: {output_csv}")
    else:
        print("[SUCCESS] Infrastructure environment matches defined compliance baselines.")

if __name__ == "__main__":
    main()
