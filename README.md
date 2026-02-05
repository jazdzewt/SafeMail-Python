# SafeMail

SafeMail is a secure web-based chat application built with Python (Flask), designed to demonstrate core concepts of cybersecurity including encryption, secure authentication, and digital signatures.

## Features

*   **User Authentication**: Secure Login and Registration system.
*   **Two-Factor Authentication (2FA)**: Time-based One-Time Password (TOTP) integration using Google Authenticator (or similar).
*   **Secure Messaging**: Messages are signed and encrypted.
*   **Digital Signatures**: Verification of message integrity and sender identity.
*   **Attachments**: Secure handling and downloading of file attachments.
*   **Security Protections**:
    *   CSRF Protection (Cross-Site Request Forgery)
    *   Rate Limiting (Protection against Brute Force/DDoS)
    *   HTTPS/SSL via Nginx Reverse Proxy
    *   Secure Headers
*   **Containerized Architecture**: Fully dockerized with separate containers for the Web App and Nginx.

## Technology Stack

*   **Backend**: Python 3.12, Flask 3.0
*   **Database**: SQLite (SQLAlchemy)
*   **Security Libraries**: `cryptography`, `pyotp`, `flask-limiter`, `flask-wtf`, `argon2-cffi`
*   **Server**: Gunicorn served behind Nginx
*   **Infrastructure**: Docker & Docker Compose

## Installation

### Prerequisites
*   [Docker](https://www.docker.com/products/docker-desktop)
*   [Git](https://git-scm.com/)

### Running with Docker (Recommended)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/jazdzewt/SafeMail-Python.git
    cd SafeMail-Python
    ```

2.  **Generate Secrets (if not present):**
    Ensure you have the necessary secret files in the `secrets/` directory (e.g., `flask_secret.txt`).

3.  **Build and Run:**
    ```bash
    docker-compose up --build
    ```

4.  **Access the Application:**
    Open your browser and navigate to:
    `https://localhost` (or `https://localhost:443`)

    > **Note:** Since this uses a self-signed certificate for development, your browser may warn you about the connection not being private. You can proceed safely (e.g., "Advanced" -> "Proceed to localhost").

## Local Development (Without Docker)

1.  **Install Dependencies:**
    ```bash
    pip install -r web/requirements.txt
    ```

2.  **Run the Application:**
    ```bash
    python web/app.py
    ```
    The app will run on `http://localhost:5000` (HTTP only, unless configured otherwise).

## Security Details

This project implements several security layers:
*   **Passwords**: Hashed securely using Argon2.
*   **Data at Rest**: Messages are stored in an encrypted format (if applicable logic is enabled).
*   **Data in Transit**: All traffic is encrypted via TLS/SSL (Nginx).
*   **Input Validation**: Strict validation of user inputs to prevent XSS and Injection attacks.

