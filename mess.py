import sqlite3
import hashlib
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import datetime
import base64

# Define the hidden directory
hidden_dir = os.path.join(os.getcwd(), ".secure_data")

# Create the hidden directory if it doesn't exist
if not os.path.exists(hidden_dir):
    os.makedirs(hidden_dir)

# Database setup
def init_db():
    db_path = os.path.join(hidden_dir, "user_data.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    salt TEXT,
                    public_key TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    timestamp TEXT,
                    encrypted_message TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    conn.commit()
    conn.close()

# Generate a random salt
def generate_salt():
    return os.urandom(16).hex()

# Hash password with salt
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Generate a new SSH key pair
def generate_ssh_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem, public_key_pem

# Register a new user
def register_user():
    conn = sqlite3.connect(os.path.join(hidden_dir, "user_data.db"))
    c = conn.cursor()
    username = input("Enter a username: ")
    password = getpass.getpass("Enter a password: ")
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    ssh_key_option = input("Do you have an SSH key? (y/n): ").strip().lower()
    if ssh_key_option == 'y':
        ssh_key_path = input("Enter the path to your SSH private key: ")
        passphrase = getpass.getpass("Enter your SSH key passphrase (if any): ")
        try:
            with open(ssh_key_path, "rb") as key_file:
                private_key = key_file.read()
            private_key_obj = serialization.load_pem_private_key(
                private_key,
                password=passphrase.encode() if passphrase else None,
                backend=default_backend()
            )
            public_key = private_key_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except (ValueError, TypeError):
            print("Failed to load the provided SSH key. Please check the path and passphrase.")
            return
    else:
        private_key, public_key = generate_ssh_key_pair()
        private_key_path = os.path.join(hidden_dir, f"{username}_private_key.pem")
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key)
        print(f"Generated new SSH key pair:\nPrivate Key saved to {private_key_path}\nPublic Key:\n{public_key.decode()}")

    try:
        c.execute("INSERT INTO users (username, password, salt, public_key) VALUES (?, ?, ?, ?)", 
                  (username, hashed_password, salt, public_key.decode()))
        conn.commit()
        print("Registration successful!")
    except sqlite3.IntegrityError:
        print("Username already exists!")
    conn.close()

# Login existing user
def login_user():
    conn = sqlite3.connect(os.path.join(hidden_dir, "user_data.db"))
    c = conn.cursor()
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    c.execute("SELECT id, password, salt, public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        user_id, stored_password, salt, public_key = result
        if hash_password(password, salt) == stored_password:
            print("Login successful!")
            return user_id, public_key
        else:
            print("Invalid password!")
    else:
        print("Username not found!")
    return None, None

# Derive a key from an SSH private key
def derive_key_from_ssh(ssh_key_path, passphrase=None):
    try:
        with open(ssh_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=passphrase.encode() if passphrase else None,
                backend=default_backend()
            )

        # Extract the key bytes from the private key
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Derive a key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'some_salt',  # Use a proper salt in production
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(key_bytes))
    except (ValueError, TypeError):
        print("Failed to derive a key from the provided SSH key. Please check the path and passphrase.")
        return None

# Encrypt a message
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Decrypt a message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Save a new message
def save_message(user_id, key):
    print("Enter your message. Press Ctrl+D (Ctrl+Z on Windows) to save it.")
    message = sys.stdin.read()
    encrypted_message = encrypt_message(message, key)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(os.path.join(hidden_dir, "user_data.db"))
    c = conn.cursor()
    c.execute("INSERT INTO messages (user_id, timestamp, encrypted_message) VALUES (?, ?, ?)",
              (user_id, timestamp, encrypted_message))
    conn.commit()
    conn.close()
    print("Message saved!")

# Recall saved messages
def recall_messages(user_id, key):
    conn = sqlite3.connect(os.path.join(hidden_dir, "user_data.db"))
    c = conn.cursor()
    c.execute("SELECT id, timestamp FROM messages WHERE user_id = ?", (user_id,))
    messages = c.fetchall()
    conn.close()
    if messages:
        for idx, (message_id, timestamp) in enumerate(messages, start=1):
            print(f"{idx}. {timestamp}")
        choice = int(input("Select a message number to recall: "))
        if 1 <= choice <= len(messages):
            message_id = messages[choice - 1][0]
            conn = sqlite3.connect(os.path.join(hidden_dir, "user_data.db"))
            c = conn.cursor()
            c.execute("SELECT encrypted_message FROM messages WHERE id = ?", (message_id,))
            encrypted_message = c.fetchone()[0]
            conn.close()
            print("Message:", decrypt_message(encrypted_message, key))
        else:
            print("Invalid choice!")
    else:
        print("No messages found!")

# Main function
def main():
    init_db()
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            register_user()
        elif choice == '2':
            user_id, public_key = login_user()
            if user_id:
                ssh_key_path = input("Enter the path to your SSH private key: ")
                passphrase = getpass.getpass("Enter your SSH key passphrase (if any): ")
                key = derive_key_from_ssh(ssh_key_path, passphrase or None)
                if key:
                    while True:
                        print("1. Save a new message")
                        print("2. Recall saved messages")
                        print("3. Logout")
                        action = input("Choose an option: ")
                        if action == '1':
                            save_message(user_id, key)
                        elif action == '2':
                            recall_messages(user_id, key)
                        elif action == '3':
                            break
                        else:
                            print("Invalid option!")
        elif choice == '3':
            break
        else:
            print("Invalid option!")

if __name__ == "__main__":
    main()
