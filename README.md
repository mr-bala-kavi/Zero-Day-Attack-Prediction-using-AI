# 🔐 Zero-Day Attack Prediction using AI

## 📘 Project Overview

This project focuses on predicting the severity of zero-day vulnerabilities using machine learning techniques applied to real-world CVE (Common Vulnerabilities and Exposures) data. Leveraging historical data from the NVD (National Vulnerability Database), the model aims to classify whether a newly reported vulnerability is likely to be critical/high or not.

---

## 📌 Problem Statement

Zero-day vulnerabilities are a major threat in cybersecurity. These are unknown or unpatched flaws exploited before developers become aware. The goal of this project is to build an AI-based system that can predict the severity of newly reported vulnerabilities based on their descriptions and metadata, helping organizations prioritize threats more efficiently.

---

## 🎯 Objectives

* Extract and preprocess structured CVE data from NVD JSON feeds
* Train a machine learning model to classify vulnerabilities
* Predict if a CVE is critical/high using both textual and structured features
* Save and reuse trained models for future batch predictions

---

## 📂 Dataset Used

### 1. `cve_data.csv`

* Historical CVE data with columns like `CVE`, `details`, `Severity`, etc.
* Preprocessed to handle missing values and clean fields

### 2. `nvdcve-1.1-2024.json`

* Official NVD JSON feed containing detailed vulnerability records for 2024
* Parsed into structured format with fields:

  * `CVE_ID`
  * `description`
  * `severity`
  * `impact_score`
  * `attack_vector`
  * `attack_complexity`
  * `privileges_required`

---

## 🛠️ Tools & Libraries

* Python 3.10+
* Pandas, NumPy
* Scikit-learn
* Joblib
* JSON (for parsing NVD feeds)
* Matplotlib/Seaborn (for optional visualization)

---

## 📈 Machine Learning Workflow

### Step 1: Data Preprocessing

* Handle missing values
* Normalize text fields
* Encode categorical features like `attack_vector`, `attack_complexity`, `privileges_required`
* Create binary label: `1` if severity is `high` or `critical`, else `0`

### Step 2: Feature Extraction

* TF-IDF vectorization on `details` or `description` field
* Combine TF-IDF vectors with structured numerical/categorical features

### Step 3: Model Training

* Algorithm: `RandomForestClassifier`
* Accuracy: \~83% (with text only) and potentially higher with structured features

### Step 4: Save Trained Artifacts

* Model saved as: `rf_model.pkl`
* Vectorizer saved as: `tfidf_vectorizer.pkl`

### Step 5: Batch Prediction

* New CVEs from 2024 predicted using saved model
* Output saved as: `nvd_2024_with_predictions.csv`

---

## 🚀 How to Run

### 1. Install dependencies:

```bash
pip install pandas scikit-learn joblib
```

### 2. Parse NVD JSON (optional):

```bash
python parse_nvd_json.py
```

### 3. Train the model:

```bash
python train_model.py
```

### 4. Predict new CVEs with user input:

```bash
python predict.py
```

You will be prompted to enter:

* CVE description
* Impact score
* Attack vector
* Attack complexity
* Privileges required

---

## 📊 Sample Prediction Output

| CVE\_ID       | description | severity | impact\_score | attack\_vector | attack\_complexity | privileges\_required | predicted\_label |
| ------------- | ----------- | -------- | ------------- | -------------- | ------------------ | -------------------- | ---------------- |
| CVE-2024-XXXX | ...         | HIGH     | 8.0           | NETWORK        | LOW                | NONE                 | CRITICAL         |
| CVE-2024-YYYY | ...         | LOW      | 3.1           | LOCAL          | HIGH               | LOW                  | Not Critical     |

---

## 📌 Future Enhancements

* Integrate Streamlit for real-time CVE analysis UI
* Extend model with deep learning (BERT/NLP models)
* Add anomaly detection for unseen attack types
* Real-time scraping from NVD API

---

## 👨‍💻 Author

**Kavi's Network (Mr-Balakavi)**
Developing Cybersecurity Researcher | Budding Ethical Hacker | AI Enthusiast
---

## 📜 License

This project is for educational and research purposes only.

---
