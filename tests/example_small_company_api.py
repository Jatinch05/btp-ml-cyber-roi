"""
Example: Test API predictions with small companies.
Shows how the API provides baseline estimates with warnings for small companies.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import requests

# Example incidents - mix of small and large companies
test_incidents = [
    {
        "Industry": "Retail",
        "Year": 2024,
        "Attack_Type": "Ransomware",
        "Data_Type": "Customer",
        "Records_Compromised": 25000,
        "Employee_Count": 85,  # SMALL - will use baseline
    },
    {
        "Industry": "Healthcare",
        "Year": 2024,
        "Attack_Type": "Data Breach",
        "Data_Type": "Medical",
        "Records_Compromised": 150000,
        "Employee_Count": 3500,  # LARGE - will use ML model
    }
]

print("="*80)
print("API REQUEST - SMALL COMPANY HANDLING DEMO")
print("="*80)

print("\nSending prediction request with 2 companies:")
print("  1. Small company: 85 employees (Retail)")
print("  2. Large company: 3,500 employees (Healthcare)")

# For testing, we'll simulate the API response by calling directly
from src.btp.infer import ImpactCatBoost
import pandas as pd

model = ImpactCatBoost()
df = pd.DataFrame(test_incidents)
predictions, is_baseline_flags = model.predict_musd(df)

print("\n" + "="*80)
print("API RESPONSE")
print("="*80)

for i, incident in enumerate(test_incidents):
    pred = predictions[i]
    is_baseline = is_baseline_flags[i]
    
    response = {
        "prediction_musd": float(pred),
        "fields_filled": []  # Would be populated by actual API
    }
    
    if is_baseline:
        response["warning"] = (
            f"⚠️ BASELINE ESTIMATE: This prediction uses a simple baseline model because "
            f"the ML model was trained exclusively on companies with 2,000+ employees. "
            f"Your company ({incident['Employee_Count']} employees) is below this threshold. "
            f"This estimate is based on industry averages and per-employee costs, "
            f"and may have higher uncertainty than ML predictions for larger companies."
        )
    
    print(f"\n--- Incident {i+1} ---")
    print(f"Company size: {incident['Employee_Count']} employees")
    print(f"Industry: {incident['Industry']}")
    print(f"Records compromised: {incident['Records_Compromised']:,}")
    print(f"\nPredicted impact: ${pred:.2f}M")
    
    if "warning" in response:
        print(f"\n{response['warning']}")
    else:
        print("\n✓ ML model prediction (high confidence)")

print("\n" + "="*80)
print("KEY TAKEAWAYS")
print("="*80)
print("• Small companies (<2,000 employees) receive baseline estimates")
print("• API clearly explains WHY baseline is used (no training data)")
print("• Large companies (≥2,000 employees) use the optimized ML model")
print("• All predictions include context about estimation method")
print("• No companies are rejected - everyone gets an estimate")
print("="*80)
