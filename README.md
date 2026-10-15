# 🛡️ Hybrid Intrusion Detection System Using AI

### Combining Rule-Based Detection and Machine Learning for Network Security

## 📌 About the Project

The **Hybrid Intrusion Detection System Using AI** is a cybersecurity project designed to identify suspicious network activity by combining rule-based detection techniques with machine learning.

The system aims to detect known suspicious patterns using predefined rules and identify potentially unusual activity through machine-learning analysis. It also includes security event logging and a dashboard for monitoring and analyzing detection results.

## 🎯 Objectives

- Detect known suspicious activities using predefined rules.
- Apply machine learning to analyze potentially abnormal network activity.
- Improve threat visibility through centralized event logging.
- Display security events and alerts through a monitoring dashboard.
- Support cybersecurity learning, analysis, and defensive security research.

## ⚙️ Key Features

- **Hybrid Detection:** Combines rule-based analysis and machine learning.
- **Suspicious Activity Analysis:** Identifies patterns that may indicate security threats.
- **Security Event Logging:** Stores detection events for further analysis.
- **Monitoring Dashboard:** Provides a visual interface for reviewing security information.
- **Dataset Analysis:** Supports testing against available network traffic datasets.

## 🧠 How It Works

1. **Data Input:** Collect or load network traffic data for analysis.
2. **Preprocessing:** Prepare the input data for detection.
3. **Rule-Based Detection:** Compare relevant activity against predefined detection rules.
4. **AI-Based Analysis:** Apply the trained machine-learning model to identify suspicious patterns.
5. **Event Logging:** Store detection results in the database.
6. **Monitoring:** Display available events and analysis results through the dashboard.

## 🏗️ System Architecture

```text
Network Traffic / Dataset
           |
           v
     Data Preprocessing
           |
           v
     Hybrid Detection
       /         \
      v           v
 Rule-Based    Machine Learning
 Detection     Analysis
       \         /
        v       v
     Detection Results
           |
           v
    SQLite Event Database
           |
           v
     Security Dashboard
```

## 🛠️ Technologies Used

- **Programming Language:** Python
- **Machine Learning:** Scikit-learn
- **Data Processing:** Pandas
- **Database:** SQLite
- **Dashboard:** Streamlit
- **Development Environment:** PyCharm
- **Version Control:** Git and GitHub

## 🚀 Getting Started

### Prerequisites

- Python 3
