import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import json

USER_DIR = "./users/"
if not os.path.exists(USER_DIR):
    os.makedirs(USER_DIR)

SALT = b'secure_salt'

def hash_password(password):
    kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def verify_password(password, hashed_password):
    try:
        kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1, backend=default_backend())
        kdf.verify(password.encode(), base64.urlsafe_b64decode(hashed_password))
        return True
    except:
        return False

def register_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    user_path = os.path.join(USER_DIR, f"{username}.json")

    if os.path.exists(user_path):
        print("User already exists.")
        return
    
    hashed_password = hash_password(password)
    user_data = {
        'username': username,
        'password': hashed_password,
        'files': {},
        'permissions': {}
    }

    with open(user_path, 'w') as f:
        json.dump(user_data, f)
    print(f"User {username} registered successfully.")

def login_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    user_path = os.path.join(USER_DIR, f"{username}.json")

    if not os.path.exists(user_path):
        print("User does not exist.")
        return None
    
    with open(user_path, 'r') as f:
        user_data = json.load(f)

    if verify_password(password, user_data['password']):
        print(f"User {username} logged in successfully.")
        return username
    else:
        print("Invalid credentials.")
        return None

def derive_key(password):
    kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(content, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(content) + encryptor.finalize()

def decrypt_file(encrypted_content, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_content) + decryptor.finalize()

def upload_file(username):
    user_path = os.path.join(USER_DIR, f"{username}.json")
    password = input("Enter your password to encrypt the file: ")
    
    filename = input("Enter the filename to upload: ")
    content = input("Enter file content: ")
    
    with open(user_path, 'r+') as f:
        user_data = json.load(f)
    
    key = derive_key(password)
    encrypted_content = encrypt_file(content.encode(), key)

    file_path = os.path.join(USER_DIR, f"{username}_{filename}.enc")
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)
    
    user_data['files'][filename] = file_path
    user_data['permissions'][filename] = {'owner': username, 'permissions': ['read', 'write']}
    
    with open(user_path, 'w') as f:
        json.dump(user_data, f)

    print(f"File '{filename}' uploaded and encrypted successfully.")

def download_file(username):
    user_path = os.path.join(USER_DIR, f"{username}.json")
    password = input("Enter your password to decrypt the file: ")

    filename = input("Enter the filename to download: ")
    
    with open(user_path, 'r') as f:
        user_data = json.load(f)

    if filename not in user_data['files']:
        print("File not found.")
        return
    
    file_path = user_data['files'][filename]
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()

    key = derive_key(password)
    content = decrypt_file(encrypted_content, key).decode()
    print(f"File '{filename}' content:\n{content}")

def main():
    while True:
        print("\nSecure File Management System")
        print("1. Register")
        print("2. Login")
        print("3. Upload File")
        print("4. Download File")
        print("5. Exit")
        
        choice = input("Enter choice: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            global logged_in_user
            logged_in_user = login_user()
        elif choice == '3':
            if logged_in_user:
                upload_file(logged_in_user)
            else:
                print("You need to log in first.")
        elif choice == '4':
            if logged_in_user:
                download_file(logged_in_user)
            else:
                print("You need to log in first.")
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

logged_in_user = None
main()

