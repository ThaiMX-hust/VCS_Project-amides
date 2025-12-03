#!/usr/bin/env python3
"""
Split benign 'all' file into train and valid sets
"""
import sys
import os
import random

def split_benign_data(all_file: str, output_dir: str, train_ratio: float = 0.8, seed: int = 42):
    """
    Split benign 'all' file into train and valid sets
    
    Args:
        all_file: Path to benign 'all' file
        output_dir: Directory to save train/valid files
        train_ratio: Ratio for train set (default 0.8 = 80%)
        seed: Random seed for reproducibility
    """
    try:
        print(f"[*] Reading file: {all_file}")
        
        # Read all samples
        with open(all_file, 'r', encoding='utf-8') as f:
            samples = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Total samples: {len(samples)}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_samples = []
        duplicates = 0
        for sample in samples:
            if sample not in seen:
                seen.add(sample)
                unique_samples.append(sample)
            else:
                duplicates += 1
        
        print(f"[*] Unique samples: {len(unique_samples)}")
        print(f"[*] Duplicates removed: {duplicates}")
        
        # Shuffle for random split
        random.seed(seed)
        random.shuffle(unique_samples)
        
        # Split
        split_point = int(len(unique_samples) * train_ratio)
        train_samples = unique_samples[:split_point]
        valid_samples = unique_samples[split_point:]
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Write train file
        train_path = os.path.join(output_dir, "train")
        with open(train_path, 'w', encoding='utf-8') as f:
            for sample in train_samples:
                f.write(f"{sample}\n")
        print(f"\n✓ Train samples: {len(train_samples)} → {train_path}")
        
        # Write valid file
        valid_path = os.path.join(output_dir, "valid")
        with open(valid_path, 'w', encoding='utf-8') as f:
            for sample in valid_samples:
                f.write(f"{sample}\n")
        print(f"✓ Valid samples: {len(valid_samples)} → {valid_path}")
        
        # Summary
        print("\n" + "="*60)
        print("Split Summary:")
        print("="*60)
        print(f"Total samples:        {len(samples)}")
        print(f"Unique samples:       {len(unique_samples)}")
        print(f"Train samples (80%):  {len(train_samples)}")
        print(f"Valid samples (20%):  {len(valid_samples)}")
        print(f"Random seed:          {seed}")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python split_benign_data.py <all_file> <output_dir> [train_ratio] [seed]")
        print("\nExample:")
        print("  python split_benign_data.py \\")
        print("    data/benign/process_creation/all \\")
        print("    data/benign/process_creation \\")
        print("    0.8 \\")
        print("    42")
        sys.exit(1)
    
    all_file = sys.argv[1]
    output_dir = sys.argv[2]
    train_ratio = float(sys.argv[3]) if len(sys.argv) > 3 else 0.8
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 42
    
    if not os.path.exists(all_file):
        print(f"❌ Error: File not found: {all_file}")
        sys.exit(1)
    
    split_benign_data(all_file, output_dir, train_ratio, seed)
