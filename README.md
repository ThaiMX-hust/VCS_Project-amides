# AMIDES — Adaptive Misuse Detection System

## 📋 Mô Tả Dự Án

**AMIDES** là hệ thống ML-based để phát hiện **command-line evasion attacks** nhắm vào Sigma detection rules trong môi trường Windows. Dự án cung cấp:

1. **Misuse Detection Model** (Binary SVM): Phân loại benign vs malicious commandlines
2. **Rule Attribution Model** (Multi-class SVM): Xác định rule nào đang bị attacker cố gắng bypass (133 Sigma rules)

### 🎯 Mục Tiêu Chính

- Phát hiện các evasion techniques mà attackers sử dụng để bypass SIEM rules
- Cung cấp explainability: xác định cụ thể rule nào đang bị evade
- Hỗ trợ blue team trong việc cải thiện detection rules

---

## 📂 Cấu Trúc Thư Mục

```
VCS_Project-amides/
├── README.md                          # Tài liệu chính
├── requirements.txt                   # Dependencies
├── .gitignore
│
├── data/                              # Datasets
│   ├── benign/process_creation/       # Benign samples
│   │   ├── all                        # Raw benign commandlines
│   │   ├── train                      # Training set (80%)
│   │   └── valid                      # Validation set (20%)
│   ├── evasion/                       # 810 evasion samples
│   │   ├── win_apt_apt29_thinktanks/
│   │   ├── win_malware_ryuk/
│   │   └── ... (133 rule folders)
│   ├── events/process_creation/       # Sigma rule matches
│   └── rule/process_creation/         # Sigma detection rules (.yml)
│
├── models/process_creation/           # Trained models
│   ├── train_rslt_misuse_svc_rules_f1_0.zip          # Misuse model
│   ├── train_rslt_misuse_svc_rules_f1_0_info.json
│   ├── multi_train_rslt_attr_svc_rules_f1_v2_0.zip   # Attribution model (133 SVMs)
│   └── multi_train_rslt_attr_svc_rules_f1_v2_0_info.json
│
├── src/
│   ├── amides/                        # Core library
│   │   ├── data.py                    # TrainingResult, MultiTrainingResult
│   │   ├── persist.py                 # Dumper for model I/O
│   │   ├── sigma.py                   # RuleDataset, RuleSetDataset
│   │   ├── evaluation.py              # Evaluation metrics
│   │   ├── events.py                  # Event loading
│   │   ├── utils.py                   # Utilities
│   │   ├── features/
│   │   │   ├── normalize.py           # Commandline normalization
│   │   │   ├── extraction.py          # Feature extraction
│   │   │   ├── tokenization.py        # Tokenizers
│   │   │   └── deduplicate.py
│   │   ├── models/
│   │   │   └── selection.py           # Hyperparameter tuning
│   │   └── scale.py                   # Scalers
│   │
│   └── scripts/                       # CLI tools
│       ├── train.py                   # Training pipeline
│       ├── validate.py                # Model validation
│       ├── classify_sample.py         # Single-sample classification
│       ├── eval_attr.py               # Rule attribution evaluation
│       ├── split_and_normalize_benign.py  # Split + normalize benign data
│       └── append_csv_to_benign.py        # Append CSV to benign

```

---

## 🚀 Hướng Dẫn Sử Dụng

### 1️⃣ Cài Đặt Môi Trường

```bash
# Clone repository
git clone <repository-url>
cd VCS_Project_amides

# Tạo virtual environment
python3 -m venv vcs-amides
source vcs-amides/bin/activate  # Linux/Mac
# hoặc: vcs-amides\Scripts\activate  # Windows

# Cài đặt dependencies
pip install -r requirements.txt
```

### 2️⃣ Chuẩn Bị Dữ Liệu Benign

**Split + Normalize **

```bash
python split_and_normalize_benign.py \
    data/benign/process_creation/all \
    data/benign/process_creation
```


**Output:**
- `data/benign/process_creation/train` (80%)
- `data/benign/process_creation/valid` (20%)

### 3️⃣ Huấn Luyện Models

#### Train Misuse Model (Binary Classification)

```bash
python src/scripts/train.py --config src/scripts/config/process_creation/train_misuse_svc_rules.json
```

**Output:**
- `models/process_creation/train_rslt_misuse_svc_rules_f1_0.zip`
- `models/process_creation/train_rslt_misuse_svc_rules_f1_0_info.json`

#### Train Attribution Model (Multi-class Classification)

```bash
python src/scripts/train.py --config src/scripts/config/process_creation/train_attr_svc_rules.json
```

**Output:**
- `models/process_creation/multi_train_rslt_attr_svc_rules_f1_v2_0.zip` (133 SVMs)
- `models/process_creation/multi_train_rslt_attr_svc_rules_f1_v2_0_info.json`


### 4️⃣ Validation

```bash
python src/scripts/validate.py --config src/scripts/config/process_creation/validate_misuse_svc_rules.json
```

```bash
python src/scripts/eval_mcc_scalling.py --config src/scripts/config/process_creation/eval_misuse_svc_rules.json
```
```bash
python src/scripts/eval_attr.py --config src/scripts/config/process_creation/eval_attr.json
```


### 5️⃣ Phát Hiện Evasion

#### Option A: Analyze từ commandline trực tiếp

```bash
python src/scripts/classify_sample.py \
    --sample "powershell.exe -NonInteractive -ExecutionPolicy bypass -enc SUVF..." \
```

#### Option B: Analyze từ file

```bash
# Từ text file
python src/scripts/classify_sample.py \
    --sample-file samples/suspicious.txt \
    --models-dir models/process_creation

# Từ JSON event
python src/scripts/classify_sample.py \
    --event-file events/sysmon_event.json \
    --models-dir models/process_creation
```


**Output ví dụ:**

```
================================================================================
Sample Classification
================================================================================
Commandline: powershell.exe -NonInteractive -ExecutionPolicy bypass...

[1] Malicious Detection
    Status: 🔴 MALICIOUS
    Score:  0.8542 (threshold: 0.5)

[2] Rule Attribution (Top 5 Rules)
    Rank   Rule Name                                          Confidence
    ------------------------------------------------------------------
    🎯 #1   PowerShell Download from URL                      0.9234
       #2   Suspicious Encoded PowerShell Command Line        0.8756
       #3   Empire PowerShell Launch Parameters               0.8123
       #4   Malicious Base64 Encoded PowerShell Keywords      0.7891
       #5   Default PowerSploit and Empire Schtasks           0.7234

================================================================================
```

---



## 📊 Thống Kê Dataset

| Component | Count | Details |
|-----------|-------|---------|
| **Sigma Rules** | 133 | Windows process creation rules |
| **Evasion Samples** | 810 | Manually crafted evasions |
| **Benign Samples** | ~20,000+ | Normalized Windows commandlines |
| **Event Matchers** | 133 | Positive samples từ Sigma filters |


## 🔧 Technical Details

### Model Architecture

#### 1. Misuse Model
- **Algorithm:** Support Vector Classification (SVC) - Linear kernel
- **Feature extraction:** TF-IDF vectorization
- **Scaler:** MinMaxScaler (symmetric, MCC-optimized)
- **Binary classification:** Benign (0) vs Malicious (1)

#### 2. Attribution Model
- **Architecture:** 133 independent binary SVM classifiers
- **Voting mechanism:** Decision function ranking
- **Feature extraction:** TF-IDF per rule
- **Scalers:** MinMaxScaler per rule




