#!/usr/bin/env python3
"""
Script to detect malicious events and identify which rule they are trying to evade.
"""

import sys
import os
import argparse
import numpy as np
from typing import List, Tuple, Optional

from amides.utils import (
    get_logger,
    set_log_level,
    read_json_file,
)
from amides.persist import Dumper, PersistError
from amides.features.extraction import CommandlineExtractor
from amides.features.normalize import normalize
from amides.data import TrainingResult, MultiTrainingResult

set_log_level("info")
_logger = get_logger("detect_evasion")

base_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../"))


misuse_model_path = os.path.join(base_dir, "src/models/process_creation/train_rslt_misuse_svc_rules_f1_0.zip")
rule_attr_model_path = os.path.join(base_dir, "src/models/process_creation/multi_train_rslt_attr_svc_rules_f1_0.zip")

# Thresholds
malicious_threshold = 0.5
min_confidence = 0.0
top_n_rules = 5

# ✅ THÊM: Global dumper
dumper = None


def init_dumper(models_dir: str):
    """Initialize Dumper with models directory"""
    global dumper
    
    try:
        if dumper is None:
            dumper = Dumper(models_dir)
            _logger.info(f"Initialized dumper with models directory: {models_dir}")
    except OSError as err:
        _logger.error(f"Failed to initialize dumper: {err}")
        sys.exit(1)


def load_model(model_path: str):
    """
    Load a trained model from pickle file.
    ✅ SỬA: Dùng global dumper và load_object()
    """
    try:
        model_name = os.path.basename(model_path).replace('.zip', '')
        
        _logger.info(f"Loading model from: {model_path}")
        result = dumper.load_object(model_name)
        
        _logger.info(f"Successfully loaded model: {model_name}")
        return result
        
    except (TypeError, PersistError, FileNotFoundError) as err:
        _logger.error(f"Error loading model from {model_path}: {err}")
        return None


def extract_and_normalize_commandline(event_data: dict) -> Optional[str]:
    """
    Extract and normalize commandline from event data.
    ✅ SỬA: Thêm hỗ trợ nested structure
    """
    try:
        commandline = None
        possible_fields = ['CommandLine', 'commandline', 'command_line', 'cmd', 'process']
        
        # Check nested structures
        if 'process' in event_data and isinstance(event_data['process'], dict):
            if 'command_line' in event_data['process']:
                commandline = event_data['process']['command_line']
        
        # Check top-level fields
        if commandline is None:
            for field in possible_fields:
                if field in event_data:
                    commandline = event_data[field]
                    break
        
        if commandline is None:
            _logger.warning("Could not find commandline field in event data")
            return None
        
        # Normalize
        normalized = normalize([commandline])
        return normalized[0] if normalized else None
        
    except Exception as err:
        _logger.error(f"Error extracting commandline: {err}")
        return None


def predict_malicious(
    misuse_result: TrainingResult, 
    commandline: str
) -> Tuple[bool, float]:
    """
    Predict if a commandline is malicious.
    ✅ SỬA: Dùng feature_extractors[0] thay vì vectorizer
    """
    try:
        # ✅ Get feature extractor
        feature_extractor = misuse_result.feature_extractors[0] if misuse_result.feature_extractors else None
        
        if feature_extractor is None:
            _logger.error("Model does not contain feature extractor")
            return False, 0.0
        
        # Transform với np.array wrapper
        feature_vector = feature_extractor.transform(np.array([commandline]))
        
        # Get decision function value
        df_value = misuse_result.estimator.decision_function(feature_vector)[0]
        
        # ✅ Scale đúng cách
        if misuse_result.scaler:
            df_value_scaled = misuse_result.scaler.transform(np.array([[df_value]])).flatten()[0]
        else:
            df_value_scaled = df_value
        
        # Check if malicious
        is_malicious = df_value_scaled >= malicious_threshold
        
        return is_malicious, float(df_value_scaled)
        
    except Exception as err:
        _logger.error(f"Error predicting malicious: {err}")
        return False, 0.0


def predict_rule_attribution(
    rule_attr_result: MultiTrainingResult,
    commandline: str,
    top_n: int = 5
) -> List[Tuple[str, float]]:
    """
    Predict which rules the commandline is trying to evade.
    ✅ SỬA: Dùng feature_extractors[0]
    """
    rule_scores = []
    
    try:
        for rule_name, result in rule_attr_result.results.items():
            # ✅ Get feature extractor
            feature_extractor = result.feature_extractors[0] if result.feature_extractors else None
            
            if feature_extractor is None:
                _logger.warning(f"No feature extractor for rule: {rule_name}")
                continue
            
            # Transform
            feature_vector = feature_extractor.transform(np.array([commandline]))
            
            # Get decision function value
            df_value = result.estimator.decision_function(feature_vector)[0]
            
            # ✅ Scale đúng cách
            if result.scaler:
                df_value_scaled = result.scaler.transform(np.array([[df_value]])).flatten()[0]
            else:
                df_value_scaled = df_value
            
            # Only include if above minimum confidence
            if df_value_scaled >= min_confidence:
                rule_scores.append((rule_name, float(df_value_scaled)))
        
        # Sort by confidence (descending)
        rule_scores.sort(key=lambda x: x[1], reverse=True)
        
        return rule_scores[:top_n]
        
    except Exception as err:
        _logger.error(f"Error predicting rule attribution: {err}")
        return []


def analyze_event(
    event_data: dict,
    misuse_result: TrainingResult,
    rule_attr_result: MultiTrainingResult,
    verbose: bool = True
) -> dict:
    """Analyze a single event for malicious behavior and rule evasion."""
    # Extract and normalize commandline
    commandline = extract_and_normalize_commandline(event_data)
    
    if commandline is None:
        return {
            'success': False,
            'error': 'Could not extract commandline from event'
        }
    
    if verbose:
        print(f"\n{'='*80}")
        print(f"Analyzing Event")
        print(f"{'='*80}")
        print(f"Commandline: {commandline[:100]}...")
        print()
    
    # Step 1: Check if malicious
    is_malicious, malicious_confidence = predict_malicious(misuse_result, commandline)
    
    if verbose:
        print(f"[1] Malicious Detection")
        print(f"    Status: {'MALICIOUS' if is_malicious else 'BENIGN'}")
        print(f"    Confidence: {malicious_confidence:.4f}")
        print()
    
    result = {
        'success': True,
        'commandline': commandline,
        'is_malicious': is_malicious,
        'malicious_confidence': malicious_confidence,
        'evaded_rules': []
    }
    
    # Step 2: If malicious, identify evaded rules
    if is_malicious:
        rule_scores = predict_rule_attribution(rule_attr_result, commandline, top_n_rules)
        
        if verbose:
            print(f"[2] Rule Attribution (Top {len(rule_scores)} Rules)")
            if rule_scores:
                print(f"    {'Rule Name':<50} {'Confidence':<10}")
                print(f"    {'-'*60}")
                for rule_name, confidence in rule_scores:
                    print(f"    {rule_name:<50} {confidence:>8.4f}")
            else:
                print("    No rules identified with sufficient confidence")
            print()
        
        result['evaded_rules'] = rule_scores
    
    if verbose:
        print(f"{'='*80}\n")
    
    return result


def analyze_event_from_file(
    event_file: str,
    misuse_result: TrainingResult,
    rule_attr_result: MultiTrainingResult
) -> dict:
    """Analyze an event from a JSON file."""
    try:
        event_data = read_json_file(event_file)
        return analyze_event(event_data, misuse_result, rule_attr_result)
    except Exception as err:
        _logger.error(f"Error reading event file: {err}")
        return {'success': False, 'error': str(err)}


def analyze_event_from_commandline(
    commandline: str,
    misuse_result: TrainingResult,
    rule_attr_result: MultiTrainingResult
) -> dict:
    """Analyze a raw commandline string."""
    event_data = {'CommandLine': commandline}
    return analyze_event(event_data, misuse_result, rule_attr_result)


def main():
    parser = argparse.ArgumentParser(
        description="Detect malicious events and identify rule evasion attempts"
    )
    parser.add_argument(
        '--event-file',
        type=str,
        help='Path to event JSON file to analyze'
    )
    parser.add_argument(
        '--commandline',
        type=str,
        help='Raw commandline string to analyze',
        default='"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NonInteractive -ExecutionPolicy bypass $encodedCommand'
    )
    parser.add_argument(
        '--misuse-model',
        type=str,
        default=misuse_model_path,
        help='Path to misuse classification model'
    )
    parser.add_argument(
        '--rule-attr-model',
        type=str,
        default=rule_attr_model_path,
        help='Path to rule attribution model'
    )
    parser.add_argument(
        '--models-dir',
        type=str,
        default=os.path.join(base_dir, "src/models/process_creation"),  # ← Thêm src/
        help='Directory containing models'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        default=0.5,
        help='Malicious detection threshold (default: 0.5)'
    )
    parser.add_argument(
        '--top-n',
        type=int,
        default=5,
        help='Number of top rules to display (default: 5)'
    )
    parser.add_argument(
        '--min-confidence',
        type=float,
        default=0.0,
        help='Minimum confidence for rule attribution (default: 0.0)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output'
    )
    
    args = parser.parse_args()
    
    # Update global settings
    global malicious_threshold, top_n_rules, min_confidence
    malicious_threshold = args.threshold
    top_n_rules = args.top_n
    min_confidence = args.min_confidence
    
    # Check inputs
    if not args.event_file and not args.commandline:
        _logger.error("Must provide either --event-file or --commandline")
        sys.exit(1)
    
    # ✅ THÊM: Initialize dumper
    init_dumper(args.models_dir)
    
    # Load models
    _logger.info("Loading models...")
    misuse_result = load_model(args.misuse_model)
    rule_attr_result = load_model(args.rule_attr_model)
    
    if not misuse_result or not rule_attr_result:
        _logger.error("Failed to load required models")
        sys.exit(1)
    
    # ✅ THÊM: Validate model types
    if not isinstance(misuse_result, TrainingResult):
        _logger.error("Misuse model is not TrainingResult type")
        sys.exit(1)
    
    if not isinstance(rule_attr_result, MultiTrainingResult):
        _logger.error("Rule attribution model is not MultiTrainingResult type")
        sys.exit(1)
    
    # Analyze event
    if args.event_file:
        result = analyze_event_from_file(
            args.event_file,
            misuse_result,
            rule_attr_result
        )
    else:
        result = analyze_event_from_commandline(
            args.commandline,
            misuse_result,
            rule_attr_result
        )
    
    if not result['success']:
        _logger.error(f"Analysis failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)
    
    # Print summary in quiet mode
    if args.quiet:
        status = "MALICIOUS" if result['is_malicious'] else "BENIGN"
        print(f"Status: {status} (confidence: {result['malicious_confidence']:.4f})")
        if result['evaded_rules']:
            print(f"Top evaded rule: {result['evaded_rules'][0][0]}")
    
    sys.exit(0)


if __name__ == "__main__":
    main()