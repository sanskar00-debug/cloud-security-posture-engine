# Cloud Security Posture Management (CSPM) & Compliance Drift Engine ☁️🛡️

## 📌 Project Overview
This repository contains a programmatic Cloud Security Posture Management (CSPM) auditing engine engineered to continuously monitor distributed cloud infrastructure states against predefined security baselines (such as the CIS Benchmarks). The engine ingests serialized asset configurations, parses them against a declarative policy schema, isolates high-severity drift violations (like publicly exposed storage buckets or unrestricted ingress firewalls), and exports structured compliance logs for executive business intelligence layers.

## 🛠️ Key Capabilities & Automated Workflows
* **Automated Baseline Verification:** Evaluates multi-tier assets across global cloud availability zones against industry-standard controls.
* **Granular Multi-Domain Scans:** Analyzes access policies across three essential vectors: Storage Enforcement (public accessibility/at-rest encryption), Network Integrity (unrestricted edge ports), and Identity Security (MFA enforcement/access key lifecycle).
* **Telemetry Data Export:** Cleanses and structures raw architectural data gaps, instantly exporting metrics into a normalized format (`cloud_compliance_drift_report.csv`) for live visualization tiers.

## 📁 Repository Structure
```text
cloud-security-posture-engine/
│
├── config/
│   └── compliance_rules.json          # Declarative security policy baselines
├── data/
│   └── mock_cloud_infrastructure.json # Serialized infrastructure configuration inventory
├── cloud_cspm_audit_engine.py         # Core Python posture evaluation runner
├── cloud_compliance_drift_report.csv  # Generated output log matrix
├── requirements.txt                   # Execution dependencies (pandas, tabulate)
└── README.md                          # Technical engineering specification brief
```

## 🚀 Local Deployment & Verification
1. **Synchronize Dependencies:** Ensure standard data processing libraries are updated locally:
   ```bash
   pip install -r requirements.txt
   ```
2. **Execute the Audit Engine:** Launch the evaluation loop via your platform-native Python runner:
   ```bash
   python cloud_cspm_audit_engine.py
   ```
