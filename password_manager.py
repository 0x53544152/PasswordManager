#!/usr/bin/env python3
import base64
import bcrypt
from cryptography.fernet import Fernet
from getpass import getpass
import hashlib
import json
import os

CREDENTIALS_FILE = 'credentials.json'

def create_account(data):
    username = input("Choose a username: ").strip()
    if not username:
        print("Choose a username.")
        return
    elif username in data['users']:
        print("Username is already taken.")
        return
    password = getpass("Choose a password: ")
    if password != getpass("Confirm password: "):
        print("Passwords do not match.")
        return
    encoded_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(encoded_password, salt).decode()
    data['users'][username] = {
        'password_hash' : password_hash,
        'credentials' : {}
    }
    with open(CREDENTIALS_FILE, 'w') as file:
        json.dump(data, file, indent=4)
    print("Account created. Please login.")


def login(data):
    username = input("Username: ").strip()
    if username not in data['users']:
        print("Username does not exist.")
        return None, None
    password = getpass("Password: ")
    encoded_password = password.encode('utf-8')
    stored_password = data['users'][username]['password_hash'].encode('utf-8')
    if not bcrypt.checkpw(encoded_password, stored_password):
        print("Incorrect password.")
        return None, None
    digest = hashlib.sha256(encoded_password).digest()
    key = base64.urlsafe_b64encode(digest)
    cipher = Fernet(key)
    print(f"Welcome {username}.")
    return username, cipher


def add_credential(data, user, cipher):
    service_name = input("Service name: ").strip()
    service_username = input("Service username: ").strip()
    service_password = getpass("Service password: ")
    encoded_service_password = service_password.encode('utf-8')
    token = cipher.encrypt(encoded_service_password).decode('utf-8')
    data['users'][user]['credentials'][service_name] = {
        'username': service_username,
        'password': token
    }
    with open(CREDENTIALS_FILE, 'w') as file:
        json.dump(data, file, indent=4)
    print("Credential added.")


def view_credentials(data, user, cipher):
    credentials = data['users'][user]['credentials']
    if not credentials:
        print("No credentials found.")
        return
    print("Stored services: ")
    for service in credentials:
        print(" >", service)
    choice = input("Choose a service to view: ").strip()
    if choice not in credentials:
        print("Service not found.")
        return
    try:
        token = credentials[choice]['password'].encode('utf-8')
        password = cipher.decrypt(token).decode('utf-8')
        print(f"{choice} -> username: {credentials[choice]['username']}, password: {password}")
    except Exception:
        print("Decryption failed.")


def update_credential(data, user, cipher):
    credentials = data['users'][user]['credentials']
    if not credentials:
        print("No credentials found.")
        return
    print("Stored services: ")
    for service in credentials:
        print(" >", service)
    service = input("Choose a service to update: ").strip()
    if service not in credentials:
        print("Service not found.")
        return
    new_username = input("New service username: ").strip()
    new_password = getpass("New service password: ")
    if new_username:
        credentials[service]['username'] = new_username
    if new_password:
        encoded_new_password = new_password.encode('utf-8')
        credentials[service]['password'] = cipher.encrypt(encoded_new_password).decode('utf-8')
    with open(CREDENTIALS_FILE, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Updated {service}.")


def delete_credential(data, user):
    credentials = data['users'][user]['credentials']
    if not credentials:
        print("No credentials found.")
        return
    print("Stored services: ")
    for service in credentials:
        print(" >", service)
    service = input("Which service do you want to delete? ").strip()
    if service not in credentials:
        print("Service not found.")
        return
    else:
        del credentials[service]
        with open(CREDENTIALS_FILE, 'w') as file:
            json.dump(data, file, indent=4)
        print(f"Deleted {service}.")


def main():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as file:
            data = json.load(file)
    else:
        data = {'users': {}}
    while True:
        print("\n*** Password Manager ***")
        print("1) Create Account")
        print("2) Login")
        print("3) Exit")
        choice = input("> ").strip()
        if choice == '1':
            create_account(data)
        elif choice == '2':
            user, cipher = login(data)
            if user:
                while True:
                    print(f"\n<-- {user}'s Credentials -->")
                    print("1) Add Credential")
                    print("2) View Credentials")
                    print("3) Update Credential")
                    print("4) Delete Credential")
                    print("5) Logout")
                    sub = input("> ").strip()
                    if sub == '1':
                        add_credential(data, user, cipher)
                    elif sub == '2':
                        view_credentials(data, user, cipher)
                    elif sub == '3':
                        update_credential(data, user, cipher)
                    elif sub == '4':
                        delete_credential(data, user)
                    elif sub == '5':
                        break
                    else:
                        print("Invalid choice.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()