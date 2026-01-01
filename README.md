# 🔐 E2EE Secure Chat Application

A secure, privacy-focused end-to-end encrypted chat application built with **Flask**,  
**SQLite**, **JavaScript**, **pyotp**, and **QR-based authentication**.  
All messages are encrypted on the client side — the server never sees plaintext.

---

## 🚀 Features

- 🔒 **End-to-End Encryption (E2EE)** — messages encrypted in browser  
- 📧 **OTP-based login** — secure email verification  
- 📱 **QR code login support**  
- 🗄️ **Lightweight SQLite database**  
- 🌐 **Render deployment ready**  
- 🔁 **Keep-alive ping integration** (GitHub Actions / cron-job.org)  
- 🧩 **Clean API layer** (Flask backend)  
- 🔑 **Client-side key generation**

---

## 🧰 Tech Stack

### **Frontend**
- HTML, CSS, JavaScript  
- Client-side RSA/AES/Hybrid encryption (based on your implementation)

### **Backend**
- Python (Flask)  
- SQLite Database  
- pyotp (OTP generation)  
- qrcode  
- smtplib for email  
- hashlib (SHA-256)  
- secrets for token generation

### **Hosting**
- Render Web Service  
- Optional: GitHub Actions ping scheduler

---

## 📂 Project Structure

/project
├── app.py
├── users.db
├── static/
│ ├── js/
│ ├── css/
│ └── images/
├── templates/
│ ├── index.html
│ └── chat.html
├── requirements.txt
├── LICENSE
└── README.md


## ⚙️ Installation & Setup

### **1. Clone the repository**
git clone https://github.com/YOUR-USERNAME/YOUR-REPO.git
cd YOUR-REPO

### **2. Install dependencies**
pip install -r requirements.txt


### **3. Run the server**
python app.py


### **4. Access the app**
http://localhost:5000



## 🔑 End-to-End Encryption Workflow

1. User enters email  
2. Server sends OTP  
3. Browser generates key pair (public/private)  
4. Public key is sent to server  
5. Messages are encrypted **in the browser**  
6. Server stores only ciphertext  
7. Receiver decrypts using their private key  

**The private key NEVER leaves the user’s device.**

---

## 📡 API Documentation

### **POST /request-otp**
Sends OTP to email.

**Body:**
{ "email": "user@example.com" }


**Response:**
{ "success": true }


### **POST /verify-otp**
Validates OTP and logs user in.


### **POST /send-message**
Sends encrypted message (ciphertext only).



### **GET /messages**
Retrieves encrypted messages.



(You can expand these based on your actual endpoints.)



## 🚀 Deployment Guide (Render)

1. Create new **Web Service**
2. Select **Python environment**
3. Connect GitHub repo or upload manually
4. Set:

**Build Command:**
pip install -r requirements.txt



**Start Command:**
python app.py



5. Deploy  
6. (Optional) Add ping job to avoid spin-down

---

## 🛡️ Security Notes

- Server stores **no plaintext messages**  
- SHA-256 used for hashing  
- Time-limited tokens for OTP  
- Private key stays **only on client-side**  
- Uses secure random generators  

---

## 🔒 License

Copyright (c) 2025 MANOJ P
All Rights Reserved.

This project is proprietary. Unauthorized copying, modification, redistribution,
or use of this software is strictly prohibited.





## ⭐ Author

**MANOJ P**
