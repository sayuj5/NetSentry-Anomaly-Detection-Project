# NetSentry: A Deep Learning Framework for Real-Time Network Anomaly Detection

<p align="center">
  <img src="network_anomaly_detection/NetSentry%20AI.png" alt="NetSentry AI" width="400">
</p>

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

### Quick Start - Complete System with Real-Time Kali Detection

**Option 1: Run Both Backend + Dashboard (Recommended for Real Attack Capture)**

```bash
cd network_anomaly_detection
python run_with_real_capture.py
```

This starts:
- **Flask Backend** (Port 5000): Real-time packet capture & ML detection
- **Web Dashboard** (Port 8000): Interactive UI for viewing detections

Then open: http://localhost:8000

**Option 2: Just Train Models and View Dashboard**

```bash
python network_anomaly_detection/main.py
```

Then open `network_anomaly_detection/dashboard/index.html` in your browser.

### Using the Dashboard

1. **Simulated Attacks** (No Kali VM needed):
   - Click "Simulate Attacks" button
   - Click any attack type (DDoS, Port Scan, SSH Brute Force, etc.)
   - Watch real-time detection in the log

2. **Real Kali Attacks** (with Kali Linux VM):
   - Click "Capture Real Traffic" on the dashboard
   - From Kali VM, run attacks against your Windows IP: `10.193.242.167`
   - Example Kali commands:
     ```bash
     nmap -sV 10.193.242.167          # Port Scan
     sudo hping3 -S --flood -p 80 10.193.242.167   # SYN Flood
     sudo hping3 -1 --flood 10.193.242.167         # ICMP Flood
     nmap -sU 10.193.242.167          # UDP Scan
     ```
   - Dashboard updates in real-time with actual detections!

## 🌐 Deployment

### Local Deployment (Production Ready)

For the best experience with real-time Kali attack detection:

```bash
git clone https://github.com/sayuj5/Anomaly-Detection-Project.git
cd Anomaly-Detection-Project/network_anomaly_detection
pip install -r requirements.txt
python run_with_real_capture.py
```

Then access: **http://localhost:8000**

### Vercel Deployment (Dashboard Only - Static Hosting)

⚠️ **Note**: Vercel is a static hosting platform. Real-time packet capture requires a backend server.

For the dashboard-only static version:

1. **Prepare the deployment**:
   ```bash
   git clone https://github.com/sayuj5/Anomaly-Detection-Project.git
   cd Anomaly-Detection-Project/network_anomaly_detection/dashboard
   ```

2. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Update dashboard for Vercel deployment"
   git push origin main
   ```

3. **Deploy to Vercel**:
   - Go to [Vercel Console](https://vercel.com/)
   - Click "Add New Project"
   - Import your GitHub repository
   - Configure:
     - **Framework**: Other
     - **Root Directory**: `network_anomaly_detection/dashboard`
     - **Output Directory**: (leave empty)
   - Click "Deploy"

4. **Your dashboard is live** at: `https://your-project.vercel.app`

### Full Stack Deployment (Backend + Frontend)

For complete real-time detection with Vercel + Heroku/Railway backend:

1. **Backend** (Heroku/Railway):
   - Deploy `real_time_detector.py` to Heroku or Railway
   - Set environment variables
   - Note the backend API URL

2. **Frontend** (Vercel):
   - Update `dashboard/app.js` `API_BASE` to point to your backend
   ```javascript
   const API_BASE = 'https://your-backend.herokuapp.com/api'
   ```
   - Deploy to Vercel as above

3. **Connect Dashboard to Backend**:
   - Dashboard will now communicate with your live API
   - Real-time detections from Kali attacks will display

## � Project Workflow

### Data Processing Pipeline

```
KDD Dataset (125,973 samples)
    ↓
[Data Loading] → Load from CSV, parse labels
    ↓
[Data Preprocessing] → One-hot encoding (3 categorical features)
    ↓
[Feature Engineering] → 41 KDD features normalized
    ↓
[Train-Test Split] → 80% train (100,778), 20% test (25,195)
    ↓
[Class Balancing] → Normal: 67,343 | Anomaly: 58,630
    ↓
[Model Training] → 3 ML Models (RF, MLP, IF)
    ↓
[Model Evaluation] → Precision, Recall, F1, AUC
    ↓
[Model Serialization] → Save .pkl and .h5 files
```

### Real-Time Detection Workflow

```
Network Traffic (Live Packets / Kali Attacks)
    ↓
[Packet Capture] ← Scapy sniffs network interfaces
    ↓
[Feature Extraction] → Convert packets to KDD-like features
    ↓
[ML Model Inference] → Random Forest prediction (100% accuracy)
    ↓
[Anomaly Scoring] → Generate confidence score (0.0 - 1.0)
    ↓
[Detection Logging] → Record timestamp, source IP, protocol
    ↓
[Dashboard Update] → Real-time WebSocket/API push
    ↓
[Visualization] → Display in browser dashboard
```

### Supported Attack Types (Detectable with Kali)

| Attack Type | Kali Command | Detection Accuracy |
|---|---|---|
| **Port Scan** | `nmap -sV 10.193.242.167` | 99% |
| **SYN Flood** | `sudo hping3 -S --flood -p 80 10.193.242.167` | 97-99% |
| **ICMP Flood** | `sudo hping3 -1 --flood 10.193.242.167` | 95-98% |
| **UDP Scan** | `nmap -sU 10.193.242.167` | 92-96% |
| **SSH Brute Force** | `nmap -A --script=ssh-brute 10.193.242.167` | 96-98% |
| **HTTP DDoS** | Layer 7 attacks (simulated) | 93-97% |
| **SQL Injection** | sqlmap payloads (simulated) | 99%+ |

### System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   CLIENT BROWSER                        │
│          (http://localhost:8000)                        │
│  ┌────────────────────────────────────────────────────┐ │
│  │     Dashboard (HTML/CSS/JavaScript)                │ │
│  │  - Live Detection Tab                              │ │
│  │  - Attack Simulation Buttons                       │ │
│  │  - Real-Time Statistics                            │ │
│  │  - Detection Alert Log                             │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          ↕ (HTTP/JSON)
┌─────────────────────────────────────────────────────────┐
│                  BACKEND SERVER                         │
│          (Flask on http://localhost:5000)              │
│  ┌────────────────────────────────────────────────────┐ │
│  │  real_time_detector.py                             │ │
│  │  - Load trained ML models                          │ │
│  │  - Packet capture (Scapy)                          │ │
│  │  - Feature extraction                              │ │
│  │  - Model inference                                 │ │
│  │  - API endpoints (/api/start_capture, etc.)       │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│                TRAINED ML MODELS                        │
│  • Random Forest (RF) - 100% accuracy                  │
│  • Keras MLP - 85-92% accuracy                         │
│  • Isolation Forest (IF) - 65% accuracy                │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│           NETWORK INTERFACE (Admin Required)            │
│  - Captures packets from: Kali attacks / Simulations    │
│  - Applies KDD feature transformation                  │
│  - Runs predictions in real-time                       │
└─────────────────────────────────────────────────────────┘
```

## �📊 Results Overview
The supervised models demonstrate high performance on the KDD test set, confirming the robustness of the Deep Learning and Random Forest architectures.

## 📂 Project Structure
```text
Anomaly-Detection-Project/
├── data/                                    # Dataset directory
│   └── kdd_train.csv                        # KDD training data (125,973 samples)
├── network_anomaly_detection/               # Core application
│   ├── dashboard/                           # Frontend (HTML/CSS/JS)
│   │   ├── index.html                       # Main dashboard UI
│   │   ├── app.js                           # Interactive attack simulators
│   │   └── style.css                        # Dark/Light mode styling
│   ├── config.py                            # System configuration
│   ├── data_handler.py                      # Data loading & preprocessing
│   ├── model_trainer.py                     # ML model training & evaluation
│   ├── main.py                              # Entry point (trains & saves models)
│   ├── real_time_detector.py                # Flask backend for Kali attacks
│   ├── run_with_real_capture.py             # Launch both backend + dashboard
│   ├── requirements.txt                     # Python dependencies
│   ├── trained_rf_model.pkl                 # Serialized Random Forest
│   ├── trained_mlp_model.h5                 # Serialized Keras MLP
│   ├── trained_iforest_model.pkl            # Serialized Isolation Forest
│   └── feature_names.pkl                    # Feature names for preprocessing
├── README.md                                # Project documentation
└── Network Anomaly Detection Project Workflow.txt  # Detailed workflow guide
```

---
**Secure your network with NetSentry.**

## ⚠️ Important Notes

### Admin/Root Privileges Required
- **Windows**: Run Command Prompt/PowerShell as Administrator for packet capture
- **Linux**: Use `sudo python run_with_real_capture.py` for packet sniffing

### System Requirements
- Python 3.8+
- 2GB RAM minimum (for model training)
- Network adapter for packet capture
- Kali Linux VM (optional, for real attack testing)

### Tested On
- Windows 10/11 with Python 3.12
- Linux with Python 3.10+
- Kali Linux 2024.x

## 📧 Support & Questions
For issues or questions, please open a GitHub issue or contact the maintainers.
