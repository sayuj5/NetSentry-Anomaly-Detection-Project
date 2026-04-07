# NetSentry: A Deep Learning Framework for Real-Time Network Anomaly Detection

![NetSentry Banner](network_anomaly_detection/dashboard/index.html) <!-- Note: This is a placeholder for a real banner if you have one -->

## Overview
NetSentry is a high-performance network anomaly detection system that leverages advanced Machine Learning and Deep Learning architectures to identify potential security threats in real-time. Built on a hybrid framework, it utilizes supervised and unsupervised learning techniques to provide a robust defense against network-based attacks.

## Key Features
- **Hybrid Detection Model**: Combines Random Forest, Keras MLP (Deep Learning), and Isolation Forest (Unsupervised) for maximum accuracy.
- **Deep Learning Architecture**: Utilizes a Multi-Layer Perceptron (MLP) with early stopping and regularization to prevent overfitting on complex network patterns.
- **Real-Time Visualization**: Interactive dashboard with light and dark mode support, providing instant insight into network health and model performance.
- **Adversarial Resiliency**: Includes tools for adversarial training and hyperparameter tuning to ensure the system remains effective against evolving threat vectors.
- **Packet Interception Simulation**: Integrated terminal for simulating live traffic capture and anomaly detection.

## Technology Stack
- **Backend**: Python (Pandas, NumPy, Scikit-Learn, TensorFlow/Keras)
- **Frontend**: HTML5, Vanilla CSS, JavaScript (ES6+)
- **Data Source**: KDD Cup 1999 Network Intrusion Dataset

## System Architecture
The framework follows a modular pipeline:
1. **Data Ingestion**: Robust loading of network traffic datasets.
2. **Preprocessing**: One-hot encoding of categorical features and label binarization.
3. **Model Training**: Orchestrated training of multiple models with cross-validation.
4. **Evaluation**: Comprehensive performance analysis via Confusion Matrices and AUC scores.
5. **Deployment**: Real-time monitoring via the NetSentry Dashboard.

## How to Run

### Prerequisites
- Python 3.8+
- Required libraries: `pip install -r network_anomaly_detection/requirements.txt`

### Running the Analysis
To train the models and generate performance plots, run the following from the root directory:
```bash
python network_anomaly_detection/main.py
```

### Accessing the Dashboard
Open `network_anomaly_detection/dashboard/index.html` in your web browser to view the interactive command center.

## Project Structure
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

## Credits
This project was developed as part of a Deep Learning framework for network security.

---
**Secure your network with NetSentry.**
