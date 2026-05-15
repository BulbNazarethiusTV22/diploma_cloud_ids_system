# Secure Cloud Storage with ML-Based Threat Detection

An intelligent cloud storage security system for detecting unauthorized access using behavioral analysis and machine learning.

## Overview

This project was developed as a diploma project and demonstrates an intelligent security system for cloud storage environments.

The system analyzes user behavior during interaction with cloud storage, extracts behavioral features from session logs, and evaluates the risk level using a machine learning model.

The goal of the project is to improve detection of suspicious and potentially malicious activity in cloud environments.

---

## Features

- User authentication and session management
- Cloud storage interaction via MinIO (S3-compatible)
- Access logging and session tracking
- Behavioral feature extraction
- Machine learning risk assessment
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
```

---

## Technologies Used

### Backend
- Python
- FastAPI

### Machine Learning
- scikit-learn
- pandas
- numpy

### Storage
- MinIO (S3-compatible storage)

### Frontend
- HTML
- CSS
- JavaScript

### Infrastructure
- Docker

---

## Machine Learning Features

The ML model uses behavioral session features:

- `log_duration`
- `log_bytes_rate`
- `payload_bytes_mean`
- `payload_bytes_std`
- `payload_bytes_skewness`
- `down_up_rate`

These features are used to evaluate abnormal user activity and calculate a risk score.

---

## Risk Levels

| Risk Level | Description |
|------------|-------------|
| LOW | Normal user activity |
| MEDIUM | Suspicious behavior detected |
| HIGH | Potential malicious activity |

High-risk sessions may be automatically added to the blacklist.

---

## Admin Dashboard

The system includes an administrator panel with:

- Logs monitoring
- Session history
- Security alerts
- Risk threshold settings
- Blacklist management
- Attack simulation

---

## Installation

### Clone repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

### Create virtual environment

```bash
python -m venv .venv
```

Activate:

Windows:
```bash
.venv\Scripts\activate
```

Linux/macOS:
```bash
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running MinIO

Run MinIO container:

```bash
docker-compose up -d
```

or:

```bash
docker run -p 9000:9000 -p 9001:9001 \
-e MINIO_ROOT_USER=minioadmin \
-e MINIO_ROOT_PASSWORD=minioadmin \
minio/minio server /data --console-address ":9001"
```

---

## Run Application

```bash
uvicorn main:app --reload
```

Application:

```text
http://localhost:8000
```

Admin panel:

```text
http://localhost:8000/admin
```



---

## Future Improvements

- Real-time session monitoring
- Sound security alerts
- Live ML prediction updates
- Integration with external cloud storage providers
- Advanced anomaly detection models

---

## Author

Nazar Bulbotko  
Bachelor Thesis Project  
Igor Sikorsky Kyiv Polytechnic Institute
