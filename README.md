# Cryptographic Identity & Access Management (IAM) Security Vault

A production-grade, local Zero-Trust password management vault engineered with Multi-Factor Authentication (MFA). The system combines local computer-vision biometrics with cryptographically enforced data-at-rest protection and RFC-compliant token validation to mitigate the risk of single-point-of-failure vulnerabilities such as leaked master credentials.

## 🔑 Key Engineering Features

*   **Zero-Trust Data-at-Rest Encryption:** Leverages a local SQLite database storage system where all dynamic payload fields, application secrets, and biometric records are cryptographically secured using Advanced Encryption Standard (AES-256) symmetric block ciphers.
*   **Biometric Authentication Pipeline:** Implements an asynchronous facial recognition gating engine using `dlib` and `face_recognition`. Webcam video captures are processed in real-time, extracting facial topologies into a 128-dimensional vector space with a strict Euclidean distance classification threshold ($<0.4$) to minimize False Acceptance Rates (FAR).
*   **Multi-Factor Gating Architecture:** Enforces a rigid Three-Factor Authentication (3FA) protocol requiring:
    1. Knowledge-based credential matching against salted, Blowfish-hashed keys (`bcrypt`).
    2. Something-you-are validation via biometric facial vector clusters.
    3. Something-you-have physical verification utilizing time-synchronized tokens (`pyotp`) mapped to a QR code generator for external authenticator app syncing.
*   **Entropy Auditing Engine:** Integrates a structural metric scanner powered by Shannon Entropy mathematics ($H = L \times \log_2(R)$) to parse asset string bit-security configurations in real-time, providing granular cryptographic threat assessments (Vulnerable, Weak, Good, Excellent).
*   **Non-Deterministic Entropy Harvesting:** Avoids predictable standard Pseudo-Random Number Generation (PRNG) vulnerabilities by enforcing the Python `secrets` Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) module to harvest system-level environmental noise.

## 🛠️ Technology Stack & Dependencies

*   **Backend Framework:** Python, Flask, Flask-Assets
*   **Database Engine:** SQLite3, SQLAlchemy ORM
*   **Computer Vision & Biometrics:** OpenCV (`cv2`), `dlib`, `face_recognition`
*   **Cryptographic Libraries:** `bcrypt`, `pyotp`, `hashlib`, `secrets`
*   **Frontend Interface:** Jinja2 Templates, HTML5, JavaScript (Async Camera APIs), Tailwind CSS

## 🚀 Setup & Local Execution

1. **Clone the repository:**
```bash
git clone [https://github.com/yourusername/biometric-vault.git](https://github.com/yourusername/biometric-vault.git)
cd biometric-vault
```

2. **Initialize the Virtual Environment:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. **Install System Dependencies (Required for Dlib/CMake compilation):**
*   **macOS:**
  ```bash
brew install cmake dlib
```
*   **Linux (Ubuntu/Debian):**
  ```bash
sudo apt-get install build-essential cmake libopenblas-dev liblapack-dev
```

4. **Install Python Packages:**
```bash
pip install -r requirements.txt
```

5. **Initialize and Execute Application:**
```bash
python app.py
```
