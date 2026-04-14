# Advanced Phishing Detection System

It is a production-ready machine learning-based web application designed to detect phishing URLs. It utilizes a **Hybrid Ensemble Model (Random Forest + XGBoost + LightGBM)** to analyze URL characteristics and predict potential security threats with high accuracy.

## Features

- **AI-Powered Detection**: Uses a Voting Classifier ensemble model trained on carefully tuned security features.
- **Real-time Scanning**: Instant analysis of URLs with confidence scores.
- **Security Dashboard**: Visualize scan statistics and threat distributions.
- **Scan History**: Persistent logging of all security scans.
- **PDF Reports**: Generate and download detailed security analysis reports.
- **Cybersecurity Theme**: Modern dark UI with glassmorphism and glowing effects.

## Technology Stack

- **Backend**: Python + Flask
- **Machine Learning**: Scikit-learn, XGBoost, LightGBM, Pandas, Joblib
- **Database**: SQLite + SQLAlchemy
- **Frontend**: HTML5, CSS3, Bootstrap 5, Chart.js, jQuery
- **PDF Generation**: FPDF

## Setup Instructions

### 1. Clone the repository
```bash
git clone <repository-url>
cd AI-Phishing-Detection
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the AI Model (Optional)
If you want to retrain the model, run the Jupyter Notebook:
```bash
jupyter notebook clean_model_training.ipynb
```
*(Running the notebook will generate the `model.pkl` and `features.pkl` files used for predictions.)*

### 5. Run the Application
```bash
python app.py
```
Access the app at `http://127.0.0.1:5000` (or the port defined by your environment).

## Feature Extraction Logic

The system utilizes Hybrid content features mapped from the dataset. Some of the aspects analyzed include:
1. **URL Patterns**: URL length, special characters, and numeric ratios.
2. **IP Presence**: Usage of IP addresses instead of domain names.
3. **Protocol Indicators**: Secure protocol (HTTPS) verification.
4. **Suspicious Keywords**: Detection of phishing-related words.
