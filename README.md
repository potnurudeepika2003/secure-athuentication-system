# 🔐 Secure Authentication System

A simple and secure **Flask-based authentication system** that allows users to register, log in, and manage their accounts with proper validation and session handling.

---

## 🚀 Features

- 🧾 User Registration & Login  
- 🔑 Password Hashing for Security  
- 📁 SQLite Database Integration  
- ⚙️ Flask-WTF Forms & Validation  
- 🎨 HTML Templates (Jinja2-based)  
- 🧠 Clean and Modular Code Structure  

---

## 🏗️ Tech Stack

- **Backend:** Python, Flask  
- **Frontend:** HTML, CSS, Jinja2  
- **Database:** SQLite3  
- **Libraries Used:** Flask, Flask-WTF, Werkzeug, WTForms  

---

## ⚡ How to Run Locally

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/secure_authentication_system.git
Navigate to the project directory

cd secure_authentication_system


Install dependencies

pip install -r requirements.txt


Run the app

python app.py


Open in browser

http://127.0.0.1:5000

🧩 Folder Structure
secure_authentication_system/
│
├── app.py
├── templates/
│   ├── register.html
│   ├── login.html
│   └── dashboard.html
├── static/
│   ├── css/
│   └── images/
├── requirements.txt
└── README.md

🛡️ Security Notes

Passwords are stored securely using hashing (Werkzeug).

Avoid using debug=True in production.

Always keep your .env file (if used) private.
