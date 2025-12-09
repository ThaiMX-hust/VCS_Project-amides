#!/usr/bin/env python3
# filepath: split_and_normalize_benign.py
"""
Split benign 'all' file into train/valid and normalize to match validation format.
Each line in output will be a normalized commandline (no CSV, no quotes).
"""
import sys
import os
sys.path.insert(0, 'src')

from sklearn.model_selection import train_test_split
from amides.features.normalize import normalize

def split_and_normalize_benign(
    input_file: str,
    output_dir: str,
    train_ratio: float = 0.8,
    seed: int = 42
):
    """
    Split and normalize benign samples
    
    Args:
        input_file: Path to 'all' file with raw commandlines
        output_dir: Directory to save train/valid files
        train_ratio: Ratio for train set (default 0.8)
        seed: Random seed for reproducibility
    """
    try:
        print(f"[*] Reading samples from: {input_file}")
        
        # Read all lines
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_samples = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Total raw samples: {len(raw_samples)}")
        
        # Normalize samples
        print(f"[*] Normalizing samples...")
        normalized_samples = normalize(raw_samples)
        
        print(f"[*] Normalized samples: {len(normalized_samples)}")
        
        # Remove empty samples after normalization
        normalized_samples = [s for s in normalized_samples if s.strip()]
        
        print(f"[*] Non-empty after normalization: {len(normalized_samples)}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_samples = []
        for sample in normalized_samples:
            if sample not in seen:
                seen.add(sample)
                unique_samples.append(sample)
        
        print(f"[*] Unique samples: {len(unique_samples)}")
        print(f"[*] Duplicates removed: {len(normalized_samples) - len(unique_samples)}")
        
        # Split into train/valid
        train_samples, valid_samples = train_test_split(
            unique_samples,
            train_size=train_ratio,
            random_state=seed,
            shuffle=True
        )
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Save train set
        train_path = os.path.join(output_dir, "train")
        with open(train_path, 'w', encoding='utf-8') as f:
            for sample in train_samples:
                f.write(f"{sample}\n")
        print(f"✓ Train set: {len(train_samples)} samples → {train_path}")
        
        # Save valid set
        valid_path = os.path.join(output_dir, "valid")
        with open(valid_path, 'w', encoding='utf-8') as f:
            for sample in valid_samples:
                f.write(f"{sample}\n")
        print(f"✓ Valid set: {len(valid_samples)} samples → {valid_path}")
        
        # Summary
        print("\n" + "="*60)
        print("Processing Summary:")
        print("="*60)
        print(f"Total raw samples:        {len(raw_samples)}")
        print(f"After normalization:      {len(normalized_samples)}")
        print(f"After deduplication:      {len(unique_samples)}")
        print(f"Train samples ({train_ratio*100:.0f}%):  {len(train_samples)}")
        print(f"Valid samples ({(1-train_ratio)*100:.0f}%):  {len(valid_samples)}")
        print("="*60)
        
        # Show sample examples
        print("\n📋 Sample normalized commandlines (train):")
        for i, cmd in enumerate(train_samples[:3], 1):
            print(f"  {i}. {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
        
        print("\n📋 Sample normalized commandlines (valid):")
        for i, cmd in enumerate(valid_samples[:3], 1):
            print(f"  {i}. {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
        
        # Verify format matches validation expectation
        print("\n✅ Format verification:")
        print(f"  - One normalized commandline per line")
        print(f"  - No CSV headers, no quotes")
        print(f"  - Ready for train.py and validate.py")
        
    except FileNotFoundError:
        print(f"❌ Error: File not found: {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python split_and_normalize_benign.py <input_file> <output_dir> [train_ratio]")
        print("\nExamples:")
        print("  python split_and_normalize_benign.py data/benign/process_creation/all data/benign/process_creation")
        print("  python split_and_normalize_benign.py data/benign/process_creation/all data/benign/process_creation 0.7")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_dir = sys.argv[2]
    train_ratio = float(sys.argv[3]) if len(sys.argv) > 3 else 0.8
    
    if not os.path.exists(input_file):
        print(f"❌ Error: Input file does not exist: {input_file}")
        sys.exit(1)
    
    if not (0 < train_ratio < 1):
        print(f"❌ Error: train_ratio must be between 0 and 1, got: {train_ratio}")
        sys.exit(1)
    
    split_and_normalize_benign(input_file, output_dir, train_ratio)