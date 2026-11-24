
# PhishShield X

### Intelligent Email Threat Investigation Platform

PhishShield X is a Python-based AI/ML project designed to investigate suspicious emails and identify potential phishing indicators.

## Features

- Email content analysis
- URL intelligence and suspicious URL detection
- Email header spoofing indicators
- SPF, DKIM and DMARC result extraction
- Social engineering indicator detection
- Machine learning-based email classification
- Explainable AI indicators
- Threat intelligence correlation
- PDF investigation reports
- SQLite-based scan history
- Security analytics dashboard

## Machine Learning Models

The training pipeline evaluates:

1. Logistic Regression
2. Support Vector Machine
3. Random Forest
4. Neural Network
5. Gradient Boosting
6. XGBoost

## Technology Stack

- Python
- Streamlit
- Pandas and NumPy
- Scikit-learn
- XGBoost
- Matplotlib and Seaborn
- SQLite
- ReportLab

## Project Structure

```text
PhishShield/
├── data/
├── models/
├── notebooks/
├── outputs/
├── pages/
├── src/
├── dashboard.py
├── train.py
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone <your-repository-url>
cd PhishShield
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Dataset

Place the phishing email dataset at:

```text
data/raw/phishing/phishing_emails.csv
```

## Train Models

```bash
python train.py
```

## Run Application

```bash
streamlit run dashboard.py
```

## Disclaimer

PhishShield X is an educational and experimental security analysis project. Its heuristic indicators and machine learning predictions are not guarantees of malicious activity. It does not perform independent SPF/DKIM/DMARC verification or actual malware scanning.
