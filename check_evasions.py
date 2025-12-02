#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

from amides.sigma import RuleSetDataset
from amides.features.extraction import CommandlineExtractor

# Load rule set
rule_set = RuleSetDataset()
rule_set.load_rule_set_data(
    events_path="data/events/process_creation",
    rules_path="data/rule/process_creation",
    evasions_base_path="data/evasion"
)

# In thống kê
print(f"Total rules loaded: {len(rule_set.rule_datasets)}")
print(f"\nRules with evasions > 0:")

rules_with_evasions = []
rules_trainable = []  # Rules có thể train được

for rule_name, rule_dataset in rule_set.rule_datasets.items():
    num_evasions = rule_dataset.evasions.size if rule_dataset.evasions else 0
    if num_evasions > 0:
        rules_with_evasions.append((rule_name, num_evasions))
        
        # Kiểm tra xem có extract được malicious samples không
        try:
            # Thử extract từ filter (như train.py làm)
            filter_samples = rule_dataset.extract_field_values_from_filter(
                search_fields=["process.command_line"]
            )
            
            if filter_samples and len(filter_samples) > 0:
                rules_trainable.append((rule_name, num_evasions, len(filter_samples)))
        except Exception as e:
            print(f"  ⚠️  {rule_name}: Cannot extract samples - {e}")
        
print(f"Found {len(rules_with_evasions)} rules with evasions")
print(f"Found {len(rules_trainable)} rules trainable (có filter samples)")

# Kiểm tra 10 rules đầu
print("\n" + "="*60)
print("First 10 rules with evasions:")
print("="*60)
for rule_name, num_evasions in rules_with_evasions[:10]:
    rule_dataset = rule_set.rule_datasets[rule_name]
    num_matches = rule_dataset.matches.size if rule_dataset.matches else 0
    num_filters = len(rule_dataset.filter) if rule_dataset.filter else 0
    
    # Kiểm tra filter samples
    filter_samples = []
    try:
        filter_samples = rule_dataset.extract_field_values_from_filter(
            search_fields=["process.command_line"]
        )
    except:
        pass
    
    print(f"  {rule_name}:")
    print(f"    - Evasions: {num_evasions}")
    print(f"    - Matches: {num_matches}")
    print(f"    - Filters: {num_filters}")
    print(f"    - Filter samples: {len(filter_samples) if filter_samples else 0}")
    print()

# So sánh với 5 rules được train trong model
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
    if rule_name in rule_set.rule_datasets:
        rule_dataset = rule_set.rule_datasets[rule_name]
        num_evasions = rule_dataset.evasions.size if rule_dataset.evasions else 0
        num_matches = rule_dataset.matches.size if rule_dataset.matches else 0
        num_filters = len(rule_dataset.filter) if rule_dataset.filter else 0
        
        filter_samples = []
        try:
            filter_samples = rule_dataset.extract_field_values_from_filter(
                search_fields=["process.command_line"]
            )
        except:
            pass
        
        print(f"  ✓ {rule_name}:")
        print(f"    - Evasions: {num_evasions}")
        print(f"    - Matches: {num_matches}")
        print(f"    - Filters: {num_filters}")
        print(f"    - Filter samples: {len(filter_samples) if filter_samples else 0}")
        print()
    else:
        print(f"  ✗ {rule_name}: NOT FOUND in dataset")
        print()