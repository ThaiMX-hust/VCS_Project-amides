#!/usr/bin/env python3
"""
Script to classify a single sample and identify evaded rules.
"""

import sys
import os
import argparse
import numpy as np
from typing import List, Tuple, Optional, Dict

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
_logger = get_logger("classify_sample")

# Base directory
base_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../"))

# Default model paths
MODELS_DIR = os.path.join(base_dir, "models/process_creation")
MISUSE_MODEL_NAME = "train_rslt_misuse_svc_rules_f1_0"
#ATTR_MODEL_NAME = "multi_train_rslt_attr_svc_rules_f1_0"
ATTR_MODEL_NAME = "multi_train_rslt_attr_svc_rules_f1_v2_0"

# Classification thresholds
DEFAULT_THRESHOLD = 0.5
MIN_CONFIDENCE = 0.0
TOP_N_RULES = 10

# Global dumper
dumper = None


class SampleClassifier:
    """Classifier for malicious detection and rule attribution"""
    
    def __init__(
        self, 
        misuse_model: TrainingResult,
        attr_model: MultiTrainingResult,
        threshold: float = DEFAULT_THRESHOLD,
        min_confidence: float = MIN_CONFIDENCE,
        top_n: int = TOP_N_RULES
    ):
        self.misuse_model = misuse_model
        self.attr_model = attr_model
        self.threshold = threshold
        self.min_confidence = min_confidence
        self.top_n = top_n
        
        # Validate models
        self._validate_models()
    
    def _validate_models(self):
        """Validate that models are properly loaded"""
        if not isinstance(self.misuse_model, TrainingResult):
            raise TypeError("Misuse model must be TrainingResult")
        
        if not isinstance(self.attr_model, MultiTrainingResult):
            raise TypeError("Attribution model must be MultiTrainingResult")
        
        if not self.misuse_model.feature_extractors:
            raise ValueError("Misuse model missing feature extractors")
        
        _logger.info("Models validated successfully")
    
    def classify(self, commandline: str, verbose: bool = True) -> Dict:
        """
        Classify a commandline sample
        
        Parameters
        ----------
        commandline : str
            Normalized commandline string
        verbose : bool
            Print detailed output
        
        Returns
        -------
        dict
            Classification results
        """
        if verbose:
            self._print_header(commandline)
        
        # Step 1: Malicious detection
        is_malicious, malicious_score = self._predict_malicious(commandline)
        
        if verbose:
            self._print_malicious_result(is_malicious, malicious_score)
        
        result = {
            'success': True,
            'commandline': commandline,
            'is_malicious': is_malicious,
            'malicious_score': malicious_score,
            'evaded_rules': []
        }
        
        # Step 2: Rule attribution (only if malicious)
        if is_malicious:
            rule_scores = self._predict_rule_attribution(commandline)
            result['evaded_rules'] = rule_scores
            
            if verbose:
                self._print_rule_attribution(rule_scores)
        
        if verbose:
            self._print_footer()
        
        return result
    
    def _predict_malicious(self, commandline: str) -> Tuple[bool, float]:
        """Predict if sample is malicious"""
        try:
            # Get feature extractor
            feature_extractor = self.misuse_model.feature_extractors[0]
            
            # Transform to feature vector
            feature_vector = feature_extractor.transform(np.array([commandline]))
            
            # Get decision function value
            df_value = self.misuse_model.estimator.decision_function(feature_vector)[0]
            
            # Scale if scaler available
            if self.misuse_model.scaler:
                df_value_scaled = self.misuse_model.scaler.transform(
                    np.array([[df_value]])
                ).flatten()[0]
            else:
                df_value_scaled = df_value
            
            # Classify
            is_malicious = df_value_scaled >= self.threshold
            
            return is_malicious, float(df_value_scaled)
        
        except Exception as err:
            _logger.error(f"Error in malicious detection: {err}")
            return False, 0.0
    
    def _predict_rule_attribution(self, commandline: str) -> List[Tuple[str, float]]:
        """Predict which rules are evaded"""
        rule_scores = []
        
        try:
            for rule_name, result in self.attr_model.results.items():
                # Get feature extractor for this rule
                feature_extractor = result.feature_extractors[0] if result.feature_extractors else None
                
                if feature_extractor is None:
                    _logger.warning(f"No feature extractor for rule: {rule_name}")
                    continue
                
                # Transform
                feature_vector = feature_extractor.transform(np.array([commandline]))
                
                # Get decision function value
                df_value = result.estimator.decision_function(feature_vector)[0]
                
                # Scale if available
                if result.scaler:
                    df_value_scaled = result.scaler.transform(
                        np.array([[df_value]])
                    ).flatten()[0]
                else:
                    df_value_scaled = df_value
                
                # Only include if above minimum confidence
                if df_value_scaled >= self.min_confidence:
                    rule_scores.append((rule_name, float(df_value_scaled)))
            
            # Sort by confidence (descending)
            rule_scores.sort(key=lambda x: x[1], reverse=True)
            
            return rule_scores[:self.top_n]
        
        except Exception as err:
            _logger.error(f"Error in rule attribution: {err}")
            return []
    
    def _print_header(self, commandline: str):
        """Print classification header"""
        print(f"\n{'='*80}")
        print(f"Sample Classification")
        print(f"{'='*80}")
        print(f"Commandline: {commandline[:100]}...")
        if len(commandline) > 100:
            print(f"             (truncated, full length: {len(commandline)} chars)")
        print()
    
    def _print_malicious_result(self, is_malicious: bool, score: float):
        """Print malicious detection result"""
        status = "🔴 MALICIOUS" if is_malicious else "🟢 BENIGN"
        print(f"[1] Malicious Detection")
        print(f"    Status: {status}")
        print(f"    Score:  {score:.4f} (threshold: {self.threshold})")
        print()
    
    def _print_rule_attribution(self, rule_scores: List[Tuple[str, float]]):
        """Print rule attribution results"""
        print(f"[2] Rule Attribution (Top {len(rule_scores)} Rules)")
        
        if rule_scores:
            print(f"    {'Rank':<6} {'Rule Name':<50} {'Confidence':<10}")
            print(f"    {'-'*66}")
            
            for idx, (rule_name, confidence) in enumerate(rule_scores, 1):
                emoji = "🎯" if idx == 1 else "  "
                print(f"    {emoji} #{idx:<3} {rule_name:<50} {confidence:>8.4f}")
        else:
            print("    ⚠️  No rules identified with sufficient confidence")
        
        print()
    
    def _print_footer(self):
        """Print classification footer"""
        print(f"{'='*80}\n")


def init_dumper(models_dir: str):
    """Initialize global Dumper"""
    global dumper
    
    try:
        if dumper is None:
            dumper = Dumper(models_dir)
            _logger.info(f"Initialized dumper with: {models_dir}")
    except OSError as err:
        _logger.error(f"Failed to initialize dumper: {err}")
        sys.exit(1)


def load_model(model_name: str):
    """
    Load model using Dumper.load_object()
    
    Parameters
    ----------
    model_name : str
        Model name with or without .zip extension
        Example: "train_rslt_misuse_svc_rules_f1_0" or "train_rslt_misuse_svc_rules_f1_0.zip"
    
    Returns
    -------
    TrainingResult or MultiTrainingResult
        Loaded model
    """
    try:
        _logger.info(f"Loading model: {model_name}")
        
        # Add .zip if not present
        if not model_name.endswith('.zip'):
            model_name = f"{model_name}.zip"
        
        # Dumper.load_object() will prepend output_path if not absolute path
        model = dumper.load_object(model_name)
        
        _logger.info(f"Successfully loaded: {model_name}")
        return model
    
    except (TypeError, PersistError, FileNotFoundError) as err:
        _logger.error(f"Error loading model {model_name}: {err}")
        
        # Print helpful debug info
        if dumper._output_path and os.path.exists(dumper._output_path):
            available = [f for f in os.listdir(dumper._output_path) if f.endswith('.zip')]
            _logger.error(f"Available models in {dumper._output_path}:")
            for model_file in available:
                _logger.error(f"  - {model_file}")
        
        return None


def extract_commandline_from_input(args) -> Optional[str]:
    """Extract and normalize commandline from various input sources"""
    
    # Priority 1: Direct commandline string
    if args.sample:
        commandlines = normalize([args.sample])
        return commandlines[0] if commandlines else None
    
    # Priority 2: Sample from text file
    if args.sample_file:
        try:
            with open(args.sample_file, 'r', encoding='utf-8') as f:
                sample = f.read().strip()
                commandlines = normalize([sample])
                return commandlines[0] if commandlines else None
        except Exception as err:
            _logger.error(f"Error reading sample file: {err}")
            return None
    
    # Priority 3: Event JSON file
    if args.event_file:
        try:
            event_data = read_json_file(args.event_file)
            
            # Try different field names
            commandline = None
            
            # Nested structure
            if 'process' in event_data and isinstance(event_data['process'], dict):
                commandline = event_data['process'].get('command_line')
            
            # Top-level fields
            if commandline is None:
                for field in ['CommandLine', 'commandline', 'command_line', 'cmd']:
                    if field in event_data:
                        commandline = event_data[field]
                        break
            
            if commandline:
                commandlines = normalize([commandline])
                return commandlines[0] if commandlines else None
            else:
                _logger.error("Could not find commandline field in event JSON")
                return None
        
        except Exception as err:
            _logger.error(f"Error reading event file: {err}")
            return None
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Classify samples and identify evaded rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Direct commandline input
  python src/scripts/classify_sample.py --sample "powershell -enc base64..."
  
  # From text file
  python src/scripts/classify_sample.py --sample-file samples/suspicious.txt
  
  # From event JSON
  python src/scripts/classify_sample.py --event-file events/sysmon_event.json
  
  # Batch processing
  for file in samples/*.txt; do
    python src/scripts/classify_sample.py --sample-file "$file" --quiet
  done
        """
    )
    
    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--sample',
        type=str,
        help='Direct commandline string to classify'
    )
    input_group.add_argument(
        '--sample-file',
        type=str,
        help='Path to text file containing commandline'
    )
    input_group.add_argument(
        '--event-file',
        type=str,
        help='Path to JSON file containing event data'
    )
    
    # Model configuration
    parser.add_argument(
        '--models-dir',
        type=str,
        default=MODELS_DIR,
        help=f'Directory containing models (default: {MODELS_DIR})'
    )
    parser.add_argument(
        '--misuse-model',
        type=str,
        default=MISUSE_MODEL_NAME,
        help=f'Misuse model name (default: {MISUSE_MODEL_NAME})'
    )
    parser.add_argument(
        '--attr-model',
        type=str,
        default=ATTR_MODEL_NAME,
        help=f'Attribution model name (default: {ATTR_MODEL_NAME})'
    )
    
    # Classification parameters
    parser.add_argument(
        '--threshold',
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f'Malicious detection threshold (default: {DEFAULT_THRESHOLD})'
    )
    parser.add_argument(
        '--min-confidence',
        type=float,
        default=MIN_CONFIDENCE,
        help=f'Minimum confidence for rule attribution (default: {MIN_CONFIDENCE})'
    )
    parser.add_argument(
        '--top-n',
        type=int,
        default=TOP_N_RULES,
        help=f'Number of top rules to display (default: {TOP_N_RULES})'
    )
    
    # Output options
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output (only print summary)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    # Extract commandline from input
    commandline = extract_commandline_from_input(args)
    
    if commandline is None:
        _logger.error("Failed to extract commandline from input")
        sys.exit(1)
    
    # Initialize dumper
    init_dumper(args.models_dir)
    
    # Load models using Dumper.load_object()
    _logger.info("Loading models...")
    misuse_model = load_model(args.misuse_model)
    attr_model = load_model(args.attr_model)
    
    if not misuse_model or not attr_model:
        _logger.error("Failed to load required models")
        sys.exit(1)
    
    # Create classifier
    try:
        classifier = SampleClassifier(
            misuse_model=misuse_model,
            attr_model=attr_model,
            threshold=args.threshold,
            min_confidence=args.min_confidence,
            top_n=args.top_n
        )
    except (TypeError, ValueError) as err:
        _logger.error(f"Failed to create classifier: {err}")
        sys.exit(1)
    
    # Classify sample
    result = classifier.classify(commandline, verbose=not args.quiet)
    
    # Output results
    if args.json:
        import json
        print(json.dumps(result, indent=2))
    elif args.quiet:
        # Print compact summary
        status = "MALICIOUS" if result['is_malicious'] else "BENIGN"
        print(f"Status: {status} (score: {result['malicious_score']:.4f})")
        
        if result['evaded_rules']:
            top_rule = result['evaded_rules'][0]
            print(f"Top rule: {top_rule[0]} (confidence: {top_rule[1]:.4f})")
    
    # Exit with appropriate code
    sys.exit(0 if result['success'] else 1)


if __name__ == "__main__":
    main()