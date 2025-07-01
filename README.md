# PasswordManager

**Password Manager CLI**

A simple command-line password manager implemented in Python. It allows multiple users to create accounts, securely store service credentials, and retrieve them using industry-standard hashing and encryption.

---

## Prerequisites

* Python 3.7 or higher installed on your system.
* A terminal or command prompt (Terminal.app, iTerm2, PowerShell, etc.).

## 1. Clone the Repository

```bash
git clone https://github.com/<YourUser>/PasswordManager.git
cd PasswordManager
```

Replace `<YourUser>` with your GitHub username.

## 2. Install Dependencies

Install the required Python packages globally or for your user:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install --user bcrypt cryptography
```

## 3. Make the Script Executable (Optional)

Grant execute permission to the script so you can run it directly:

```bash
chmod +x password_manager.py
```

## 4. Run the Password Manager

You can start the program using one of the following commands:

```bash
# If executable:
./password_manager.py

# Or explicitly via Python:
python3 password_manager.py
```

## 5. Using the CLI Menu

Once launched, you will see:

```
*** Password Manager ***
1) Create Account
2) Login
3) Exit
>
```

Follow the prompts:

1. **Create Account** — Choose a unique username and password (hidden input).
2. **Login** — Enter your credentials to unlock your credential vault.
3. **Add Credential** — Store a service name, username, and password.
4. **View Credentials** — List services and decrypt a chosen password.
5. **Update Credential** — Change the username or password for a service.
6. **Delete Credential** — Remove a service entry.
7. **Logout** or **Exit** — Quit the credential vault or program.

## 6. Data Storage

All user accounts and encrypted credentials are stored in `credentials.json` in the project folder. **Do not commit this file to version control.**

---
