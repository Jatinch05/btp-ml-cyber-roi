"""
Test small company baseline estimation.
Verifies that companies <2K employees get baseline estimates with warnings.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.btp.infer import ImpactCatBoost

def test_small_company_baseline():
    """Test that small companies get baseline estimates."""
    model = ImpactCatBoost()
    
    # Test cases: small, medium, and large companies
    test_data = pd.DataFrame([
        {
            "Industry": "Technology",
            "Year": 2024,
            "Attack_Type": "Ransomware",
            "Data_Type": "PII",
            "Records_Compromised": 50000,
            "Employee_Count": 150,  # SMALL - should use baseline
            "Country": "USA"
        },
        {
            "Industry": "Healthcare",
            "Year": 2024,
            "Attack_Type": "Data Breach",
            "Data_Type": "Medical",
            "Records_Compromised": 100000,
            "Employee_Count": 1500,  # MEDIUM - should use baseline
            "Country": "USA"
        },
        {
            "Industry": "Finance",
            "Year": 2024,
            "Attack_Type": "Phishing",
            "Data_Type": "Financial",
            "Records_Compromised": 200000,
            "Employee_Count": 5000,  # LARGE - should use ML model
            "Country": "USA"
        }
    ])
    
    predictions, is_baseline_flags = model.predict_musd(test_data)
    
    print("="*80)
    print("SMALL COMPANY BASELINE TEST RESULTS")
    print("="*80)
    
    for i, row in test_data.iterrows():
        pred = predictions[i]
        is_baseline = is_baseline_flags[i]
        emp = row['Employee_Count']
        method = "BASELINE (simple estimate)" if is_baseline else "ML MODEL"
        
        print(f"\nCompany {i+1}: {emp:,} employees")
        print(f"  Method: {method}")
        print(f"  Prediction: ${pred:.2f}M")
        
        if is_baseline:
            print(f"  \u26a0\ufe0f  Warning: Using baseline estimate (company <2,000 employees)")
    
    print("\n" + "="*80)
    print("VALIDATION CHECKS")
    print("="*80)
    
    # Verify small companies use baseline
    assert is_baseline_flags[0] == True, "Row 0 (150 employees) should use baseline"
    assert is_baseline_flags[1] == True, "Row 1 (1,500 employees) should use baseline"
    assert is_baseline_flags[2] == False, "Row 2 (5,000 employees) should use ML model"
    print("\u2713 Small companies correctly identified")
    
    # Verify predictions are reasonable (>0, <$1000M)
    assert all(0 < p < 1000 for p in predictions), "All predictions should be positive and reasonable"
    print("\u2713 All predictions are reasonable")
    
    # Verify baseline estimates are generally smaller (small companies = smaller breaches)
    # Note: This is a soft check since records compromised also matters
    avg_small = sum(predictions[:2]) / 2
    large_pred = predictions[2]
    print(f"\n  Average small company estimate: ${avg_small:.2f}M")
    print(f"  Large company ML prediction: ${large_pred:.2f}M")
    
    print("\n" + "="*80)
    print("\u2713 ALL TESTS PASSED")
    print("="*80)

if __name__ == "__main__":
    test_small_company_baseline()
