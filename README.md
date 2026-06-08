# Secure Cloud Storage with ML-Based Threat Detection

An intelligent cloud storage security system for detecting unauthorized access using behavioral analysis and machine learning.

## Overview

This project was developed as a bachelor diploma project and demonstrates an intelligent security system for detecting unauthorized access to cloud storage environments.

The system analyzes user behavior during interaction with cloud storage, extracts behavioral features from session logs, and evaluates the risk level using a machine learning model.

The goal of the project is to improve the detection of suspicious and potentially malicious activity in cloud environments through behavioral analysis and automated risk assessment.

---

## Features

- User authentication and session management
- Cloud storage interaction via MinIO (S3-compatible storage)
- Access logging and session tracking
- Behavioral feature extraction
- Machine learning-based risk assessment
- Security alerts generation
- Automatic IP blacklisting for high-risk activity
- Admin dashboard for monitoring
- Risk threshold configuration
- Attack simulation module
- Paginated logs view

---

## System Architecture

```text
User
   ↓
FastAPI Backend
   ↓
Logging System
   ↓
Feature Extraction
   ↓
ML Model
   ↓
Decision Engine
   ↓
MinIO Storage
````

---

## Technologies Used

### Backend

* Python
* FastAPI
* JWT Authentication

### Machine Learning

* scikit-learn
* pandas
* numpy

### Storage

* MinIO (S3-compatible object storage)

### Frontend

* HTML
* CSS
* JavaScript

### Infrastructure

* Docker

### Development Tools

* VS Code
* Swagger UI
* GitHub

---

## Machine Learning Features

The ML model uses behavioral session features:

* `log_duration`
* `log_bytes_rate`
* `payload_bytes_mean`
* `payload_bytes_std`
* `payload_bytes_skewness`
* `down_up_rate`

These features are used to evaluate abnormal user activity and calculate a risk score.

---

## Risk Levels

| Risk Level | Description                  |
| ---------- | ---------------------------- |
| LOW        | Normal user activity         |
| MEDIUM     | Suspicious behavior detected |
| HIGH       | Potential malicious activity |

High-risk sessions may be automatically added to the blacklist.

---

## Admin Dashboard

The system includes an administrator panel with:

* Logs monitoring
* Session history
* Security alerts
* Risk threshold settings
* Blacklist management
* Attack simulation

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/2026-TV-22/Bulbotko_NV.git
cd Bulbotko_NV
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
```

Activate environment:

**Windows**

```bash
.venv\Scripts\activate
```

**Linux/macOS**

```bash
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Download ML Models

Machine learning model files are not included in the repository due to GitHub file size limitations.

### Step 1 — Create `models` directory

Create a `models` folder in the root project directory.

Expected project structure:

```text
Bulbotko_NV/
│── app/
│── notebooks/
│── models/      ← create this folder
│── requirements.txt
│── docker-compose.yml
│── main.py
```

### Step 2 — Download trained models

Download the archive with trained ML models:

**Google Drive archive:**
https://drive.google.com/drive/folders/1MONCU1YALG-s8ImEiNDP0Uaj1PDZajuz?usp=sharing

### Step 3 — Extract files

Extract the downloaded archive into the `models` folder.

The directory should contain:

```text
models/
│── rf_cloud_ids.pkl
│── scaler.pkl
```

---

## Running MinIO

Run MinIO using Docker Compose:

```bash
docker-compose up -d
```

or manually:

```bash
docker run -p 9000:9000 -p 9001:9001 ^
-e MINIO_ROOT_USER=minioadmin ^
-e MINIO_ROOT_PASSWORD=minioadmin ^
minio/minio server /data --console-address ":9001"
```

MinIO Console:

```text
http://localhost:9001
```

Default credentials:

```text
Username: minioadmin
Password: minioadmin
```

---

## Run Application

Start FastAPI server:

```bash
uvicorn main:app --reload
```

Application URL:

```text
http://localhost:8000
```

Swagger API documentation:

```text
http://localhost:8000/docs
```

Admin panel:

```text
http://localhost:8000/admin
```

---

## Future Improvements

* Real-time session monitoring
* Sound security alerts
* Live ML prediction updates
* Integration with external cloud storage providers
* Advanced anomaly detection models

---

## Author

**Nazar Bulbotko**
Bachelor Thesis Project
Igor Sikorsky Kyiv Polytechnic Institute

```
```
