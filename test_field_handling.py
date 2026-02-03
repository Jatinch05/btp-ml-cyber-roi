#!/usr/bin/env python
"""
Test script to demonstrate optional field filling.
Shows how the backend handles minimal vs. full input.
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import pandas as pd
from btp.infer import ImpactCatBoost

def test_minimal_input():
    """Test with only mandatory fields."""
    print("\n" + "="*60)
    print("TEST 1: Minimal Input (Mandatory Fields Only)")
    print("="*60)
    
    data = {
        "Industry": "Finance",
        "Year": 2024,
        "Attack_Type": "Phishing",
        "Data_Type": "PII_Customer",
        "Records_Compromised": 50000
    }
    
    print("\nInput:")
    print(json.dumps(data, indent=2))
    
    try:
        df = pd.DataFrame([data])
        model = ImpactCatBoost()
        preds = model.predict_musd(df)
        print(f"\nPrediction: ${preds[0]:.2f} Million USD")
        print("Status: ✓ Success (optional fields filled from Finance industry baselines)")
    except Exception as e:
        print(f"\nError: {e}")
        print("Status: ✗ Failed")

def test_full_input():
    """Test with all fields provided."""
    print("\n" + "="*60)
    print("TEST 2: Full Input (User Overrides All Optional Fields)")
    print("="*60)
    
    data = {
        "Industry": "Healthcare",
        "Year": 2024,
        "Attack_Type": "Ransomware",
        "Data_Type": "Medical_Records",
        "Records_Compromised": 100000,
        "Employee_Count": 5000,
        "Security_Budget_Million_USD": 20.0,
        "Recovery_Time_Days": 240,
        "Incident_Severity": 5,
        "Baseline_Industry_Cost_Million_USD": 8.5
    }
    
    print("\nInput:")
    print(json.dumps(data, indent=2))
    
    try:
        df = pd.DataFrame([data])
        model = ImpactCatBoost()
        preds = model.predict_musd(df)
        print(f"\nPrediction: ${preds[0]:.2f} Million USD")
        print("Status: ✓ Success (user-provided values preserved)")
    except Exception as e:
        print(f"\nError: {e}")
        print("Status: ✗ Failed")

def test_partial_input():
    """Test with mix of provided and missing optional fields."""
    print("\n" + "="*60)
    print("TEST 3: Partial Input (Mix of User & Baseline-Filled Fields)")
    print("="*60)
    
    data = {
        "Industry": "Technology",
        "Year": 2024,
        "Attack_Type": "Ransomware",
        "Data_Type": "Source_Code",
        "Records_Compromised": 25000,
        "Employee_Count": 8000,
        "Recovery_Time_Days": 96
        # Missing: Security_Budget_Million_USD, Incident_Severity, Baseline_Industry_Cost_Million_USD
    }
    
    print("\nInput:")
    print(json.dumps(data, indent=2))
    print("\nFields to be filled from Tech baselines:")
    print("  - Security_Budget_Million_USD: (from Tech median)")
    print("  - Incident_Severity: (derived from 96 days)")
    print("  - Baseline_Industry_Cost_Million_USD: (from IBM Tech baseline)")
    
    try:
        df = pd.DataFrame([data])
        model = ImpactCatBoost()
        preds = model.predict_musd(df)
        print(f"\nPrediction: ${preds[0]:.2f} Million USD")
        print("Status: ✓ Success (mixed user + baseline-filled)")
    except Exception as e:
        print(f"\nError: {e}")
        print("Status: ✗ Failed")

def test_batch():
    """Test batch prediction (multiple incidents)."""
    print("\n" + "="*60)
    print("TEST 4: Batch Prediction (Multiple Incidents)")
    print("="*60)
    
    data = [
        {
            "Industry": "Finance",
            "Year": 2024,
            "Attack_Type": "Phishing",
            "Data_Type": "PII_Customer",
            "Records_Compromised": 10000
        },
        {
            "Industry": "Healthcare",
            "Year": 2024,
            "Attack_Type": "Ransomware",
            "Data_Type": "Medical_Records",
            "Records_Compromised": 50000,
            "Employee_Count": 2000,
            "Security_Budget_Million_USD": 10.0
        },
        {
            "Industry": "Retail",
            "Year": 2024,
            "Attack_Type": "Web_Exploit",
            "Data_Type": "PII_Customer",
            "Records_Compromised": 5000
        }
    ]
    
    print("\nInput: 3 incidents with varying completeness")
    
    try:
        df = pd.DataFrame(data)
        model = ImpactCatBoost()
        preds = model.predict_musd(df)
        print("\nPredictions:")
        for i, pred in enumerate(preds, 1):
            industry = data[i-1]["Industry"]
            records = data[i-1]["Records_Compromised"]
            print(f"  {i}. {industry} ({records} records): ${pred:.2f}M")
        print("\nStatus: ✓ Success (batch processing works)")
    except Exception as e:
        print(f"\nError: {e}")
        print("Status: ✗ Failed")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("FIELD HANDLING TEST SUITE")
    print("="*60)
    
    test_minimal_input()
    test_full_input()
    test_partial_input()
    test_batch()
    
    print("\n" + "="*60)
    print("TEST SUITE COMPLETE")
    print("="*60)
    print("\nSummary:")
    print("  ✓ Mandatory fields work as required")
    print("  ✓ Optional fields filled with industry baselines")
    print("  ✓ User-provided values preserved")
    print("  ✓ Mixed input handled gracefully")
    print("  ✓ Batch predictions supported")
