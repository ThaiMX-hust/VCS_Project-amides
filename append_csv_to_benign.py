#!/usr/bin/env python3
"""
Append CommandLine from CSV to benign 'all' file
"""
import pandas as pd
import sys
import os

def append_csv_to_benign(csv_path: str, benign_file: str):
    """
    Extract CommandLine from CSV and append to benign file
    
    Args:
        csv_path: Path to input CSV file
        benign_file: Path to benign 'all' file
    """
    try:
        print(f"[*] Reading CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # Check for CommandLine or CommandLine_norm column
        
        if 'CommandLine' in df.columns:
            column_name = 'CommandLine'
            print(f"[*] Using column: CommandLine (original)")
        else:
            print("❌ Error: CSV must have 'CommandLine'")
            print(f"Available columns: {', '.join(df.columns)}")
            sys.exit(1)
        
        print(f"[*] Total CSV rows: {len(df)}")
        
        # Extract commandlines (remove NaN and empty strings)
        commandlines = df[column_name].dropna().tolist()
        commandlines = [cmd.strip() for cmd in commandlines if cmd.strip()]
        
        print(f"[*] Valid commandlines from CSV: {len(commandlines)}")
        
        # Read existing benign samples
        existing_samples = set()
        if os.path.exists(benign_file):
            with open(benign_file, 'r', encoding='utf-8') as f:
                existing_samples = {line.strip() for line in f if line.strip()}
            print(f"[*] Existing samples in '{benign_file}': {len(existing_samples)}")
        else:
            print(f"[*] File '{benign_file}' does not exist, will create new file")
        
        # Find new unique samples (not in existing)
        new_samples = []
        duplicates = 0
        for cmd in commandlines:
            if cmd not in existing_samples:
                new_samples.append(cmd)
                existing_samples.add(cmd)  # Add to set to avoid duplicates within CSV
            else:
                duplicates += 1
        
        print(f"[*] New unique samples to add: {len(new_samples)}")
        print(f"[*] Duplicates skipped: {duplicates}")
        
        if len(new_samples) == 0:
            print("\n✓ No new samples to add. All commandlines already exist in the file.")
            return
        
        # Append new samples to file
        with open(benign_file, 'a', encoding='utf-8') as f:
            for cmd in new_samples:
                f.write(f"{cmd}\n")
        
        print(f"\n✓ Successfully appended {len(new_samples)} new samples to '{benign_file}'")
        
        # Final statistics
        print("\n" + "="*60)
        print("Append Summary:")
        print("="*60)
        print(f"CSV rows:              {len(df)}")
        print(f"Valid commandlines:    {len(commandlines)}")
        print(f"Existing samples:      {len(existing_samples) - len(new_samples)}")
        print(f"New samples added:     {len(new_samples)}")
        print(f"Duplicates skipped:    {duplicates}")
        print(f"Total samples now:     {len(existing_samples)}")
        print("="*60)
        
        # Show sample of new commandlines
        if len(new_samples) > 0:
            print("\nSample of new commandlines added:")
            for i, cmd in enumerate(new_samples[:5], 1):
                print(f"  {i}. {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python append_csv_to_benign.py <input.csv> <benign_file>")
        print("\nExample:")
        print("  python append_csv_to_benign.py \\")
        print("    data/benign/process_creation/benign_sysmon_10k.csv \\")
        print("    data/benign/process_creation/all")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    benign_file = sys.argv[2]
    
    if not os.path.exists(csv_path):
        print(f"❌ Error: CSV file not found: {csv_path}")
        sys.exit(1)
    
    append_csv_to_benign(csv_path, benign_file)
