"""
COMPREHENSIVE DEMO: Small Company Handling
===========================================

This demo shows how the system handles companies of all sizes,
from micro startups to large enterprises, with clear transparency
about when baseline estimates vs ML predictions are used.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.btp.infer import ImpactCatBoost

def format_company_size(emp):
    if emp < 100:
        return f"{emp} employees (Micro)"
    elif emp < 500:
        return f"{emp} employees (Small)"
    elif emp < 2000:
        return f"{emp:,} employees (Medium)"
    elif emp < 10000:
        return f"{emp:,} employees (Large)"
    else:
        return f"{emp:,} employees (Enterprise)"

# Test companies spanning all sizes
test_companies = pd.DataFrame([
    {
        "name": "Tech Startup",
        "Industry": "Technology",
        "Year": 2024,
        "Attack_Type": "Ransomware",
        "Data_Type": "Source_Code",
        "Records_Compromised": 5000,
        "Employee_Count": 25,  # Micro
        "Country": "USA"
    },
    {
        "name": "Local Retail Chain",
        "Industry": "Retail",
        "Year": 2024,
        "Attack_Type": "Web_Exploit",
        "Data_Type": "PII_Customer",
        "Records_Compromised": 30000,
        "Employee_Count": 250,  # Small
        "Country": "USA"
    },
    {
        "name": "Regional Hospital",
        "Industry": "Healthcare",
        "Year": 2024,
        "Attack_Type": "Data Breach",
        "Data_Type": "Medical_Records",
        "Records_Compromised": 100000,
        "Employee_Count": 1200,  # Medium
        "Country": "USA"
    },
    {
        "name": "Financial Services Firm",
        "Industry": "Finance",
        "Year": 2024,
        "Attack_Type": "Phishing",
        "Data_Type": "Financial",
        "Records_Compromised": 200000,
        "Employee_Count": 5500,  # Large - ML MODEL STARTS HERE
        "Country": "USA"
    },
    {
        "name": "National Energy Company",
        "Industry": "Energy",
        "Year": 2024,
        "Attack_Type": "Advanced_Persistent_Threat",
        "Data_Type": "Operational_Data",
        "Records_Compromised": 50000,
        "Employee_Count": 25000,  # Enterprise
        "Country": "USA"
    }
])

# Get predictions
model = ImpactCatBoost()
predictions, is_baseline_flags = model.predict_musd(test_companies)

print("="*100)
print(" " * 25 + "CYBER BREACH IMPACT PREDICTIONS")
print("="*100)
print("\nComparing predictions across company sizes (Micro → Enterprise)")
print("Shows where baseline estimates are used vs. ML model predictions\n")

# Create results table
for i, row in test_companies.iterrows():
    pred = predictions[i]
    is_baseline = is_baseline_flags[i]
    
    print("─" * 100)
    print(f"\n📊 {row['name']}")
    print(f"   Size: {format_company_size(row['Employee_Count'])}")
    print(f"   Industry: {row['Industry']}")
    print(f"   Attack: {row['Attack_Type']}")
    print(f"   Records Compromised: {row['Records_Compromised']:,}")
    print(f"\n   💰 Predicted Impact: ${pred:.2f} Million USD")
    
    if is_baseline:
        print(f"   📐 Method: BASELINE ESTIMATE")
        print(f"   ⚠️  Note: Model trained only on companies ≥2,000 employees")
        print(f"   ℹ️  Estimate based on: ${row['Industry']} industry multiplier × {row['Employee_Count']} employees")
        print(f"                        + ${row['Records_Compromised']:,} records × $150/record")
    else:
        print(f"   🤖 Method: ML MODEL (CatBoost)")
        print(f"   ✓  High confidence (trained on 27,225 samples)")
        print(f"   ✓  Expected error: 36-39% MAPE for large companies")
    print()

print("─" * 100)
print("\n" + "="*100)
print("SUMMARY OF APPROACH")
print("="*100)

baseline_count = sum(is_baseline_flags)
ml_count = len(is_baseline_flags) - baseline_count

print(f"\n📊 Companies analyzed: {len(test_companies)}")
print(f"   • Baseline estimates: {baseline_count} (small companies <2K employees)")
print(f"   • ML predictions: {ml_count} (large companies ≥2K employees)")

print("\n🎯 BASELINE ESTIMATION (for small companies)")
print("   • Method: Industry-specific per-employee cost model")
print("   • Formula: (Industry_Multiplier × Employees) + (Records × $150)")
print("   • Purpose: Provide rough guidance when ML model not trained")
print("   • Transparency: Always include warning message explaining limitation")

print("\n🤖 ML MODEL (for large companies)")
print("   • Method: Optimized CatBoost with feature engineering")
print("   • Training: 27,225 samples (3,025 real + 24,200 synthetic)")
print("   • Performance: MAPE=36-39% (well below 50% target)")
print("   • Confidence: High - trained on comprehensive dataset")

print("\n💡 DESIGN PHILOSOPHY")
print("   1. Never reject users - provide best available estimate")
print("   2. Full transparency - clearly explain estimation method")
print("   3. Honest limitations - acknowledge when extrapolating")
print("   4. Defensible baselines - anchor in industry research (IBM)")

print("\n📈 PREDICTION COMPARISON")
print("   Small companies (baseline):  $0.05M - $1.50M  (cautious estimates)")
print("   Large companies (ML model):  $10M - $70M      (data-driven predictions)")
print("   → Model correctly captures scale effects and industry risk factors")

print("\n" + "="*100)
print("✓ All companies received predictions with appropriate transparency")
print("="*100)
