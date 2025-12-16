# 🛡️ IntrusionNet Sentinel: Real-Time ML-Powered NIDS

## Project Overview

**IntrusionNet Sentinel** is a sophisticated Network Intrusion Detection System (NIDS) designed for real-time threat analysis. It employs machine learning classification (specifically a trained **Random Forest** model using `scikit-learn`) to continuously monitor network traffic, extract flow-based features, and instantly classify network connections as **Normal** or **Attack/Anomalous**.

This system is built upon a modular, two-stage architecture:
1.  **Training Stage:** Preprocessing and training the detection model on labeled NIDS datasets (e.g., NSL-KDD).
2.  **Detection Stage:** Real-time packet sniffing and prediction using the trained model assets.



## 🚀 Key Features

* **Real-Time Classification:** Utilizes flow-based features (duration, byte counts) for rapid threat assessment.
* **Machine Learning Core:** Employs a **Random Forest Classifier** for high accuracy and robust anomaly detection.
* **Asset Persistence:** Saves the trained model, scaler, and feature map using `joblib` for seamless deployment.
* **Simulation Mode:** Includes a built-in simulation environment for testing the detection logic without requiring administrator privileges or specialized network drivers (Npcap).

## 💻 Technology Stack

| Technology | Role |
| :--- | :--- |
| **Python** | Core programming language. |
| **Scapy** | Network packet capture and creation (Used in Detection/Simulation). |
| **scikit-learn** | Machine learning framework for classification and model training. |
| **Pandas/NumPy** | Data manipulation and feature engineering. |
| **joblib** | Model persistence (saving and loading the trained model). |

## ⚙️ Setup and Installation

### 1. Prerequisites

You must have Python (3.8+) installed.

### 2. Install Dependencies

Open your terminal or command prompt and run:

```bash
pip install pandas scikit-learn scapy joblib
