# NetSentry: A Deep Learning Framework for Real-Time Network Anomaly Detection

An end-to-end machine learning project for detecting network intrusions (anomalies) using the KDD (Knowledge Discovery and Data Mining) dataset. The pipeline compares the effectiveness of supervised tree-based, deep learning, and unsupervised models for binary classification (Normal vs. Anomaly).

## 🚀 Key Features
- **Hybrid Detection Model**: Combines Random Forest, Keras MLP (Deep Learning), and Isolation Forest (Unsupervised) for maximum accuracy.
- **Deep Learning Architecture**: Utilizes a Multi-Layer Perceptron (MLP) with early stopping and regularization.
- **Real-Time Visualization**: Interactive dashboard with light and dark mode support.
- **Performance Metrics**: Generates detailed Classification Reports, AUC scores, Confusion Matrices, and Feature Importance plots.
- **Adversarial Resiliency**: Includes tools for adversarial training and hyperparameter tuning.

## 🛠️ Project Setup

### Prerequisites
Ensure you have Python 3.8+ and Git installed on your system.

### 1. Clone the Repository
```bash
git clone https://github.com/sayuj5/Anomaly-Detection-Project.git
cd Anomaly-Detection-Project
```

### 2. Set up the Environment
It is highly recommended to use a virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r network_anomaly_detection/requirements.txt
```

### 4. Data Preparation
Place your KDD training dataset file inside a `data/` folder and name it `kdd_train.csv`.

## ▶️ Execution

### Running the Analysis
To train the models and generate performance plots:
```bash
python network_anomaly_detection/main.py
```

### Accessing the Dashboard
Open `network_anomaly_detection/dashboard/index.html` in your web browser to view the interactive command center.

## 📊 Results Overview
The supervised models demonstrate high performance on the KDD test set, confirming the robustness of the Deep Learning and Random Forest architectures.

## 📂 Project Structure
```text
├── data/                       # Dataset directory
├── network_anomaly_detection/   # Core logic
│   ├── dashboard/              # Frontend components
│   ├── config.py               # System configuration
│   ├── data_handler.py         # Data processing logic
│   ├── main.py                 # Entry point
│   ├── model_trainer.py        # Model training and evaluation
│   └── requirements.txt        # Python dependencies
└── README.md                   # Project documentation
```

---
**Secure your network with NetSentry.**
