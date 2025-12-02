#!/usr/bin/env python3
"""
Script để debug xem tại sao chỉ 5 rules được train
"""
import sys
sys.path.insert(0, 'src')

from amides.sigma import RuleSetDataset, RuleDatasetError
from amides.features.extraction import CommandlineExtractor
from amides.features.normalize import normalize
from amides.data import DataBunch

# Load rule set
rule_set = RuleSetDataset()
rule_set.load_rule_set_data(
    events_path="data/events/process_creation",
    rules_path="data/rule/process_creation",
    evasions_base_path="data/evasion"
)

print(f"Total rules loaded: {len(rule_set.rule_datasets)}\n")

# Load benign samples
benign_samples = []
try:
    with open("data/benign/process_creation/train", "r") as f:
        benign_samples = [line.strip() for line in f if line.strip()]
    print(f"Loaded {len(benign_samples)} benign samples\n")
except Exception as e:
    print(f"Error loading benign samples: {e}\n")

rules_trainable = []
rules_failed = []

for rule_name, rule_dataset in rule_set.rule_datasets.items():
    num_evasions = rule_dataset.evasions.size if rule_dataset.evasions else 0
    
    # Skip rules without evasions (như trong _train_models)
    if num_evasions == 0:
        continue
    
    # Try to prepare training data (như trong prepare_training_data)
    try:
        # Extract malicious samples from filter
        malicious_samples = rule_dataset.extract_field_values_from_filter(
            search_fields=["process.command_line"]
        )
        
        if not malicious_samples or len(malicious_samples) == 0:
            rules_failed.append((rule_name, "No malicious samples from filter"))
            continue
        
        # Normalize
        malicious_samples = normalize(malicious_samples)
        
        if len(malicious_samples) == 0:
            rules_failed.append((rule_name, "No samples after normalization"))
            continue
            
        # Create DataBunch (simplified check)
        if len(benign_samples) > 0:
            rules_trainable.append((rule_name, num_evasions, len(malicious_samples)))
        else:
            rules_failed.append((rule_name, "No benign samples"))
            
    except RuleDatasetError as e:
        rules_failed.append((rule_name, f"RuleDatasetError: {e}"))
    except ValueError as e:
        rules_failed.append((rule_name, f"ValueError: {e}"))
    except Exception as e:
        rules_failed.append((rule_name, f"Unexpected error: {e}"))

print(f"✓ Rules trainable: {len(rules_trainable)}")
print(f"✗ Rules failed: {len(rules_failed)}\n")

if len(rules_failed) > 0:
    print("="*60)
    print("Failed rules:")
    print("="*60)
    for rule_name, error in rules_failed[:20]:  # Show first 20
        print(f"  {rule_name}")
        print(f"    Error: {error}")
        print()

print("="*60)
print("First 10 trainable rules:")
print("="*60)
for rule_name, num_evasions, num_malicious in rules_trainable[:10]:
    print(f"  {rule_name}")
    print(f"    - Evasions: {num_evasions}")
    print(f"    - Malicious samples: {num_malicious}")
    print()

# Check the 5 rules that were actually trained
print("="*60)
print("Checking the 5 rules that were trained in the model:")
print("="*60)
trained_rules = [
    "Adwind RAT / JRAT",
    "Suspicious Curl Usage on Windows",
    "Suspicious Use of Procdump",
    "Scheduled Task Creation",
    "Java Running with Remote Debugging"
]

for rule_name in trained_rules:
    if rule_name in [r[0] for r in rules_trainable]:
        idx = [r[0] for r in rules_trainable].index(rule_name)
        _, num_evasions, num_malicious = rules_trainable[idx]
        print(f"  ✓ {rule_name}: OK ({num_evasions} evasions, {num_malicious} malicious samples)")
    else:
        # Find in failed
        failed_match = [r for r in rules_failed if r[0] == rule_name]
        if failed_match:
            print(f"  ✗ {rule_name}: FAILED - {failed_match[0][1]}")
        else:
            print(f"  ? {rule_name}: NOT FOUND")
