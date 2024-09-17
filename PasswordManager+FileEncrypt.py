import os
import sys
import json
import hashlib
import keyring
import base64
import shutil
import re
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from tkinter import ttk
import pyotp
import qrcode
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

# Constants
SERVICE_NAME = 'CrossPlatformPasswordManager'
CREDENTIAL_KEYS = [
    'master_password',
    'salt',
    'encrypted_symmetric_key',
    '2fa_secret'  # Added for 2FA
]
KEY_DIRECTORY = 'keys'  # Directory to store encrypted RSA keys
DATA_FILE = 'passwords.json'

# Ensure the key directory exists
if not os.path.exists(KEY_DIRECTORY):
    os.makedirs(KEY_DIRECTORY)

def print_status(message):
    """
    Logs informational messages to the console.
    In production, consider using the logging module for better log management.
    """
    print(f"[INFO] {message}")

def is_strong_password(password):
    """
    Checks if the password meets the following criteria:
    - At least 8 characters
    - Contains both uppercase and lowercase letters
    - Includes digits
    - Contains special characters
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def sanitize_input(user_input):
    """
    Sanitizes user input to prevent injection attacks.
    Allows letters, numbers, spaces, underscores, hyphens, at symbols, and periods.
    """
    if re.fullmatch(r'[A-Za-z0-9 _\-@.]+', user_input):
        return True
    return False

def generate_salt():
    """
    Generates a 128-bit (16 bytes) random salt.
    """
    return os.urandom(16)

def hash_password_with_salt(password, salt):
    """
    Hashes the password with the provided salt using SHA-256.
    Returns the hash digest.
    """
    sha256 = hashlib.sha256()
    sha256.update(salt + password.encode('utf-8'))
    return sha256.digest()

def derive_key(password_hash, salt):
    """
    Derives a symmetric encryption key from the password hash and salt using PBKDF2HMAC.
    Returns a base64-encoded key suitable for Fernet.
    """
    print_status("Deriving encryption key from hashed password and salt.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for Fernet
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_hash))
    return key

def store_master_password(password_hash_hex):
    """
    Stores the hashed master password in the secure vault.
    """
    print_status("Storing hashed master password in secure vault.")
    try:
        keyring.set_password(SERVICE_NAME, 'master_password', password_hash_hex)
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to store master password: {e}")
        raise

def retrieve_stored_password():
    """
    Retrieves the stored hashed master password from the secure vault.
    Returns the hash as a hexadecimal string or None if not found.
    """
    print_status("Retrieving stored hashed master password from secure vault.")
    try:
        stored = keyring.get_password(SERVICE_NAME, 'master_password')
        return stored  # Return as hex string for comparison
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to retrieve master password: {e}")
        raise

def store_salt(salt):
    """
    Stores the salt in the secure vault.
    """
    print_status("Storing salt in secure vault.")
    try:
        encoded_salt = base64.b64encode(salt).decode('utf-8')
        keyring.set_password(SERVICE_NAME, 'salt', encoded_salt)
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to store salt: {e}")
        raise

def retrieve_salt():
    """
    Retrieves the stored salt from the secure vault.
    Returns the salt as bytes or None if not found.
    """
    print_status("Retrieving salt from secure vault.")
    try:
        stored_salt = keyring.get_password(SERVICE_NAME, 'salt')
        return base64.b64decode(stored_salt) if stored_salt else None
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to retrieve salt: {e}")
        raise

def store_encrypted_symmetric_key(encrypted_symmetric_key_b64):
    """
    Stores the encrypted symmetric key in the secure vault.
    """
    print_status("Storing encrypted symmetric key in secure vault.")
    try:
        keyring.set_password(SERVICE_NAME, 'encrypted_symmetric_key', encrypted_symmetric_key_b64)
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to store encrypted symmetric key: {e}")
        raise

def retrieve_encrypted_symmetric_key():
    """
    Retrieves the encrypted symmetric key from the secure vault.
    Returns the key as a base64-encoded string or None if not found.
    """
    print_status("Retrieving encrypted symmetric key from secure vault.")
    try:
        encrypted_key = keyring.get_password(SERVICE_NAME, 'encrypted_symmetric_key')
        return encrypted_key
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to retrieve encrypted symmetric key: {e}")
        raise

def generate_rsa_keys():
    """
    Generates an RSA key pair.
    Returns the private and public keys.
    """
    print_status("Generating RSA key pair.")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def store_rsa_private_key_file(private_key, symmetric_key):
    """
    Encrypts and stores the RSA private key in an encrypted file.
    """
    print_status("Storing RSA private key in encrypted file.")
    try:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        fernet = Fernet(symmetric_key)
        encrypted_pem = fernet.encrypt(pem)
        with open(os.path.join(KEY_DIRECTORY, 'private_key.pem.enc'), 'wb') as f:
            f.write(encrypted_pem)
    except Exception as e:
        print(f"[ERROR] Failed to store RSA private key in file: {e}")
        raise

def store_rsa_public_key_file(public_key, symmetric_key):
    """
    Encrypts and stores the RSA public key in an encrypted file.
    """
    print_status("Storing RSA public key in encrypted file.")
    try:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fernet = Fernet(symmetric_key)
        encrypted_pem = fernet.encrypt(pem)
        with open(os.path.join(KEY_DIRECTORY, 'public_key.pem.enc'), 'wb') as f:
            f.write(encrypted_pem)
    except Exception as e:
        print(f"[ERROR] Failed to store RSA public key in file: {e}")
        raise

def retrieve_rsa_private_key_file(symmetric_key):
    """
    Retrieves and decrypts the RSA private key from the encrypted file.
    Returns the RSA private key object.
    """
    print_status("Retrieving RSA private key from encrypted file.")
    try:
        with open(os.path.join(KEY_DIRECTORY, 'private_key.pem.enc'), 'rb') as f:
            encrypted_pem = f.read()
        fernet = Fernet(symmetric_key)
        pem = fernet.decrypt(encrypted_pem)
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
        )
        return private_key
    except Exception as e:
        print(f"[ERROR] Failed to retrieve RSA private key from file: {e}")
        raise

def retrieve_rsa_public_key_file(symmetric_key):
    """
    Retrieves and decrypts the RSA public key from the encrypted file.
    Returns the RSA public key object.
    """
    print_status("Retrieving RSA public key from encrypted file.")
    try:
        with open(os.path.join(KEY_DIRECTORY, 'public_key.pem.enc'), 'rb') as f:
            encrypted_pem = f.read()
        fernet = Fernet(symmetric_key)
        pem = fernet.decrypt(encrypted_pem)
        public_key = serialization.load_pem_public_key(
            pem,
        )
        return public_key
    except Exception as e:
        print(f"[ERROR] Failed to retrieve RSA public key from file: {e}")
        raise

def encrypt_secret(secret, symmetric_key):
    """
    Encrypts a secret string using the symmetric key.
    Returns the encrypted secret as a string.
    """
    fernet = Fernet(symmetric_key)
    encrypted_secret = fernet.encrypt(secret.encode('utf-8')).decode('utf-8')
    return encrypted_secret

def decrypt_secret(encrypted_secret, symmetric_key):
    """
    Decrypts an encrypted secret string using the symmetric key.
    Returns the decrypted secret as a string.
    """
    fernet = Fernet(symmetric_key)
    decrypted_secret = fernet.decrypt(encrypted_secret.encode('utf-8')).decode('utf-8')
    return decrypted_secret

def setup_2fa(symmetric_key):
    """
    Sets up Two-Factor Authentication (2FA) by generating a TOTP secret,
    displaying it as a QR code, and storing it securely.
    """
    # Generate a TOTP secret
    totp_secret = pyotp.random_base32()

    # Create a provisioning URI
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name="CrossPlatformPasswordManager", issuer_name="PasswordManagerApp")

    # Generate QR code
    qr = qrcode.make(uri)
    qr.show()  # Displays the QR code for the user to scan

    # Provide instructions for the user
    print_status("2FA Setup Instructions:")
    print("1. Open your preferred authenticator app (e.g., Google Authenticator, Authy).")
    print("2. Scan the displayed QR code with your authenticator app.")
    print("3. Ensure the code generated matches the one in your app.")

    # Detailed instructions in message box
    message = ("Two-Factor Authentication (2FA) Setup:\n\n"
               "1. Open your authenticator app (e.g., Google Authenticator, Authy).\n"
               "2. Add a new account and scan the displayed QR code.\n"
               "3. Enter the 6-digit code generated by your authenticator app to verify setup.\n\n"
               "For Android users, ensure your authenticator app is installed from the Google Play Store.")
    messagebox.showinfo("2FA Setup", message)

    # Encrypt and store the TOTP secret
    try:
        encrypted_secret = encrypt_secret(totp_secret, symmetric_key)
        keyring.set_password(SERVICE_NAME, '2fa_secret', encrypted_secret)
        print_status("2FA setup completed. Scan the QR code with your authenticator app.")
    except keyring.errors.KeyringError as e:
        print(f"[ERROR] Failed to store 2FA secret: {e}")
        raise

def verify_2fa_code(symmetric_key):
    """
    Verifies the TOTP code entered by the user.
    Returns True if the code is valid, False otherwise.
    """
    encrypted_secret = keyring.get_password(SERVICE_NAME, '2fa_secret')
    if not encrypted_secret:
        print_status("2FA is not set up.")
        return True  # Proceed without 2FA if not set up

    try:
        totp_secret = decrypt_secret(encrypted_secret, symmetric_key)
    except Exception as e:
        print(f"[ERROR] Failed to decrypt 2FA secret: {e}")
        raise ValueError("Failed to retrieve 2FA secret.")

    totp = pyotp.TOTP(totp_secret)

    # Prompt user for the TOTP code
    code = simpledialog.askstring("2FA Verification", "Enter the 6-digit code from your authenticator app:")

    if not code:
        raise ValueError("2FA code is required.")

    if totp.verify(code, valid_window=1):
        print_status("2FA verification successful.")
        return True
    else:
        raise ValueError("Invalid 2FA code.")

def initialize_password_manager_gui(master_password):
    """
    Initializes the password manager by setting up or verifying the master password.
    Returns the symmetric key for encryption/decryption.
    """
    print_status("Retrieving stored hashed master password from secure vault.")
    stored_password_hash = retrieve_stored_password()
    if stored_password_hash is None:
        print_status("No master password found. Setting up a new master password.")
        if not is_strong_password(master_password):
            raise ValueError("Master password does not meet strength requirements.")

        # Generate a new salt
        salt = generate_salt()

        # Hash the master password with the new salt
        password_hash = hash_password_with_salt(master_password, salt)

        # Store the hashed password and salt
        try:
            store_master_password(password_hash.hex())
            store_salt(salt)
        except Exception as e:
            raise RuntimeError("Failed to store master password and salt.") from e

        # Derive symmetric key
        symmetric_key = derive_key(password_hash, salt)

        # Generate RSA keys
        private_key, public_key = generate_rsa_keys()
        try:
            store_rsa_private_key_file(private_key, symmetric_key)
            store_rsa_public_key_file(public_key, symmetric_key)
        except Exception as e:
            raise RuntimeError("Failed to store RSA keys in files.") from e

        # Derive symmetric key and encrypt it with RSA public key
        try:
            encrypted_symmetric_key = public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode('utf-8')
            store_encrypted_symmetric_key(encrypted_symmetric_key_b64)
        except Exception as e:
            raise RuntimeError("Failed to store encrypted symmetric key.") from e

        print_status("Master password set, RSA keys generated, and encryption key derived.")

        # Setup 2FA
        setup_2fa(symmetric_key)

        # Automatically log in after setup
        return symmetric_key
    else:
        # Retrieve the stored salt
        salt = retrieve_salt()
        if not salt:
            raise ValueError("Salt not found.")

        # Hash the entered master password with the retrieved salt
        password_hash = hash_password_with_salt(master_password, salt)

        # Compare the newly hashed password with the stored hash
        if password_hash.hex() != stored_password_hash:
            raise ValueError("Incorrect master password.")

        # Retrieve and decrypt symmetric key using RSA private key
        encrypted_symmetric_key = retrieve_encrypted_symmetric_key()
        if not encrypted_symmetric_key:
            raise ValueError("Encrypted symmetric key not found.")

        try:
            private_key = retrieve_rsa_private_key_file(derive_key(password_hash, salt))
        except Exception as e:
            raise ValueError("Failed to retrieve RSA private key from file.") from e

        try:
            symmetric_key = private_key.decrypt(
                base64.b64decode(encrypted_symmetric_key),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise ValueError("Failed to decrypt symmetric key.") from e

        print_status("Master password verified and encryption key derived using RSA.")

        # Verify 2FA Code
        verify_2fa_code(symmetric_key)

        return symmetric_key

def load_data():
    """
    Loads the passwords data from the JSON file.
    Returns the data as a dictionary.
    """
    if not os.path.exists(DATA_FILE):
        print_status("Data file not found. Creating a new one.")
        return {}
    with open(DATA_FILE, 'r') as f:
        try:
            data = json.load(f)
            print_status("Loaded existing data file.")
            return data
        except json.JSONDecodeError:
            print("[ERROR] Data file is corrupted.")
            sys.exit(1)

def save_data(data):
    """
    Saves the passwords data to the JSON file.
    """
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    print_status("Data file saved.")

def mask_service_name(service):
    """
    Masks the service name by showing only the first and last letters with 10 asterisks in between.
    Example: 'gmail' -> 'g**********l'
    """
    if len(service) < 2:
        return service  # Can't mask properly
    return f"{service[0]}{'*' * 10}{service[-1]}"

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Cross-Platform Password Manager")
        self.key = None
        self.data = {}
        self.logged_in = False  # Track login state
        self.setup_gui()

    def setup_gui(self):
        """
        Sets up the main GUI with tabs for Login, Manage Passwords, Encrypt Files, and Backup & Recovery.
        """
        tab_control = ttk.Notebook(self.master)

        self.tab_login = ttk.Frame(tab_control)
        self.tab_manage = ttk.Frame(tab_control)
        self.tab_encrypt = ttk.Frame(tab_control)
        self.tab_backup = ttk.Frame(tab_control)

        tab_control.add(self.tab_login, text='Login')
        tab_control.add(self.tab_manage, text='Manage Passwords')
        tab_control.add(self.tab_encrypt, text='Encrypt Files')
        tab_control.add(self.tab_backup, text='Backup & Recovery')
        tab_control.pack(expand=1, fill="both")

        self.create_login_tab()
        self.create_manage_tab()
        self.create_encrypt_tab()
        self.create_backup_tab()

        # Initially disable tabs that require login
        tab_control.tab(self.tab_manage, state='disabled')
        tab_control.tab(self.tab_encrypt, state='disabled')
        tab_control.tab(self.tab_backup, state='disabled')

    def create_login_tab(self):
        """
        Creates the Login tab with separate frames for Setup and Login based on application state.
        """
        frame = self.tab_login

        # Provide instructions
        instructions = ("Welcome to the Cross-Platform Password Manager.\n\n"
                        "Please set up a master password to secure your data.\n"
                        "This is the **only password** you will set up.\n"
                        "Once set, **you cannot reset or change it**.\n"
                        "Ensure your password meets the following criteria:\n"
                        "- At least 8 characters\n"
                        "- Contains uppercase and lowercase letters\n"
                        "- Includes digits\n"
                        "- Contains special characters")
        ttk.Label(frame, text=instructions, justify='left').grid(column=0, row=0, columnspan=2, padx=10, pady=10, sticky='w')

        # Determine if a master password is already set
        try:
            stored_password_hash = retrieve_stored_password()
        except Exception:
            stored_password_hash = None

        if stored_password_hash is None:
            # No master password set; show setup frame
            self.setup_frame = ttk.Frame(frame)
            self.setup_frame.grid(column=0, row=1, columnspan=2, padx=10, pady=10, sticky='w')

            ttk.Label(self.setup_frame, text="Set Master Password:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
            self.new_master_password_entry = ttk.Entry(self.setup_frame, show='*', width=30)
            self.new_master_password_entry.grid(column=1, row=0, padx=10, pady=10)

            ttk.Label(self.setup_frame, text="Confirm Password:").grid(column=0, row=1, padx=10, pady=10, sticky='w')
            self.confirm_master_password_entry = ttk.Entry(self.setup_frame, show='*', width=30)
            self.confirm_master_password_entry.grid(column=1, row=1, padx=10, pady=10)

            ttk.Button(self.setup_frame, text="Set Password", command=self.handle_setup).grid(column=0, row=2, columnspan=2, pady=10)
        else:
            # Master password exists; show login frame
            self.login_frame = ttk.Frame(frame)
            self.login_frame.grid(column=0, row=1, columnspan=2, padx=10, pady=10, sticky='w')

            ttk.Label(self.login_frame, text="Enter Master Password:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
            self.master_password_entry = ttk.Entry(self.login_frame, show='*', width=30)
            self.master_password_entry.grid(column=1, row=0, padx=10, pady=10)

            ttk.Button(self.login_frame, text="Login", command=self.handle_login).grid(column=0, row=1, columnspan=2, pady=10)

            # Add Reset Master Password button
            ttk.Button(self.login_frame, text="Reset Master Password", command=self.reset_master_password_gui).grid(column=0, row=2, columnspan=2, pady=5)

    def handle_setup(self):
        """
        Handles the setup of the master password.
        """
        password = self.new_master_password_entry.get()
        confirm_password = self.confirm_master_password_entry.get()

        if not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in both password fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if not is_strong_password(password):
            messagebox.showerror("Error", "Master password does not meet strength requirements:\n- At least 8 characters\n- Contains uppercase and lowercase letters\n- Includes digits\n- Contains special characters")
            return

        try:
            self.key = initialize_password_manager_gui(password)
            self.data = load_data()
            messagebox.showinfo("Success", "Master password and 2FA setup successfully!\n\n"
                                            "IMPORTANT: This is the only password you have set.\n"
                                            "You cannot reset or change it. Please remember it carefully.")
            # Automatically log in after setup
            self.logged_in = True
            self.enable_authenticated_tabs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set master password: {e}")

    def handle_login(self):
        """
        Handles the login process by verifying the master password and deriving the encryption key.
        """
        master_password = self.master_password_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Please enter the master password.")
            return

        try:
            self.key = initialize_password_manager_gui(master_password)
            self.data = load_data()
            self.logged_in = True
            messagebox.showinfo("Success", "Logged in successfully!")
            # Enable other tabs and disable login tab
            self.enable_authenticated_tabs()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def enable_authenticated_tabs(self):
        """
        Enables tabs that require authentication and disables the Login tab.
        """
        tab_control = self.master.nametowidget(self.master.winfo_children()[0])
        tab_control.tab(self.tab_manage, state='normal')
        tab_control.tab(self.tab_encrypt, state='normal')
        tab_control.tab(self.tab_backup, state='normal')
        tab_control.select(self.tab_manage)  # Switch to Manage Passwords tab

        # Disable Login tab to prevent multiple login attempts
        tab_control.tab(self.tab_login, state='disabled')

    def create_manage_tab(self):
        """
        Creates the Manage Passwords tab with options to add and retrieve passwords.
        Additionally, adds a masked services table and a "Show All Services" button.
        """
        frame = self.tab_manage

        # Provide instructions
        instructions = ("Manage your passwords securely.\n\n"
                        "Add new entries or retrieve existing ones.")
        ttk.Label(frame, text=instructions, justify='left').grid(column=0, row=0, columnspan=3, padx=10, pady=10, sticky='w')

        ttk.Button(frame, text="Add New Password", command=self.add_password_gui).grid(column=0, row=1, padx=10, pady=10, sticky='ew')
        ttk.Button(frame, text="Retrieve Password", command=self.retrieve_password_gui).grid(column=1, row=1, padx=10, pady=10, sticky='ew')
        ttk.Button(frame, text="Show All Services", command=self.show_all_services_gui).grid(column=2, row=1, padx=10, pady=10, sticky='ew')

        # Configure grid to make buttons expand equally
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, weight=1)

        # Add Treeview for services
        self.services_tree = ttk.Treeview(frame, columns=("Service"), show='headings', height=10)
        self.services_tree.heading("Service", text="Service")
        self.services_tree.grid(column=0, row=2, columnspan=3, padx=10, pady=10, sticky='nsew')

        # Add scrollbar to the Treeview
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.services_tree.yview)
        self.services_tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(column=3, row=2, sticky='ns', pady=10)

        # Populate the services table with masked service names
        self.populate_services_table()

    def populate_services_table(self):
        """
        Populates the services Treeview with masked service names.
        """
        # Clear existing entries
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)

        # Insert masked service names
        for service in self.data.keys():
            masked_service = mask_service_name(service)
            self.services_tree.insert('', 'end', values=(masked_service,))

    def create_encrypt_tab(self):
        """
        Creates the Encrypt Files tab with options to encrypt and decrypt files.
        """
        frame = self.tab_encrypt

        # Provide instructions
        instructions = ("Encrypt and decrypt your files securely.\n\n"
                        "Choose a file to encrypt or decrypt using your master password.")
        ttk.Label(frame, text=instructions, justify='left').grid(column=0, row=0, columnspan=2, padx=10, pady=10, sticky='w')

        ttk.Button(frame, text="Encrypt File", command=self.encrypt_file_gui).grid(column=0, row=1, padx=10, pady=10, sticky='ew')
        ttk.Button(frame, text="Decrypt File", command=self.decrypt_file_gui).grid(column=1, row=1, padx=10, pady=10, sticky='ew')

        # Configure grid to make buttons expand equally
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

    def create_backup_tab(self):
        """
        Creates the Backup & Recovery tab with options to backup data, restore data, and reset the password manager.
        """
        frame = self.tab_backup

        # Provide instructions
        instructions = ("Backup and restore your data to ensure you don't lose your passwords.\n\n"
                        "Only accessible after logging in.")
        ttk.Label(frame, text=instructions, justify='left').grid(column=0, row=0, columnspan=3, padx=10, pady=10, sticky='w')

        ttk.Button(frame, text="Backup Data", command=self.backup_data).grid(column=0, row=1, padx=10, pady=10, sticky='ew')
        ttk.Button(frame, text="Restore Data", command=self.restore_data).grid(column=1, row=1, padx=10, pady=10, sticky='ew')
        ttk.Button(frame, text="Reset Password Manager", command=self.reset_password_manager_gui).grid(column=2, row=1, padx=10, pady=10, sticky='ew')

        # Configure grid to make buttons expand equally
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, weight=1)

    def add_password_gui(self):
        """
        Opens a window to add a new password entry.
        """
        add_window = tk.Toplevel(self.master)
        add_window.title("Add New Password")

        ttk.Label(add_window, text="Service:").grid(column=0, row=0, padx=10, pady=5, sticky='w')
        service_entry = ttk.Entry(add_window, width=30)
        service_entry.grid(column=1, row=0, padx=10, pady=5)

        ttk.Label(add_window, text="Username:").grid(column=0, row=1, padx=10, pady=5, sticky='w')
        username_entry = ttk.Entry(add_window, width=30)
        username_entry.grid(column=1, row=1, padx=10, pady=5)

        ttk.Label(add_window, text="Password:").grid(column=0, row=2, padx=10, pady=5, sticky='w')
        password_entry = ttk.Entry(add_window, show='*', width=30)
        password_entry.grid(column=1, row=2, padx=10, pady=5)

        # Tooltip for password strength (Removed in response to requirements)
        # password_strength_info = ("Password must be at least 8 characters long and include:\n"
        #                           "- Uppercase and lowercase letters\n"
        #                           "- Numbers\n"
        #                           "- Special characters")
        # ttk.Label(add_window, text=password_strength_info, foreground='gray').grid(column=0, row=3, columnspan=2, padx=10, pady=5, sticky='w')

        def save_password():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()

            if not service or not username or not password:
                messagebox.showerror("Error", "All fields are required.")
                return

            if not sanitize_input(service):
                messagebox.showerror("Error", "Service name contains invalid characters.")
                return

            if not sanitize_input(username):
                messagebox.showerror("Error", "Username contains invalid characters.")
                return

            # **Removed strong password check for service passwords**
            # if not is_strong_password(password):
            #     messagebox.showerror("Error", "Password does not meet strength requirements:\n- At least 8 characters\n- Contains uppercase and lowercase letters\n- Includes digits\n- Contains special characters")
            #     return

            try:
                fernet = Fernet(self.key)
                encrypted_password = fernet.encrypt(password.encode('utf-8')).decode('utf-8')

                self.data[service] = {
                    'username': username,
                    'password': encrypted_password
                }
                save_data(self.data)
                messagebox.showinfo("Success", f"Password for '{service}' added.")
                add_window.destroy()
                # Update the services table
                self.populate_services_table()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add password: {e}")

        ttk.Button(add_window, text="Save", command=save_password).grid(column=0, row=3, columnspan=2, pady=10)

    def retrieve_password_gui(self):
        """
        Opens a window to retrieve an existing password entry.
        """
        retrieve_window = tk.Toplevel(self.master)
        retrieve_window.title("Retrieve Password")

        ttk.Label(retrieve_window, text="Service:").grid(column=0, row=0, padx=10, pady=5, sticky='w')
        service_entry = ttk.Entry(retrieve_window, width=30)
        service_entry.grid(column=1, row=0, padx=10, pady=5)

        def show_password():
            service = service_entry.get().strip()
            if not service:
                messagebox.showerror("Error", "Please enter the service name.")
                return

            if not sanitize_input(service):
                messagebox.showerror("Error", "Service name contains invalid characters.")
                return

            if service in self.data:
                try:
                    fernet = Fernet(self.key)
                    decrypted_password = fernet.decrypt(self.data[service]['password'].encode('utf-8')).decode('utf-8')
                    messagebox.showinfo("Password Retrieved", f"Service: {service}\nUsername: {self.data[service]['username']}\nPassword: {decrypted_password}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt password: {e}")
            else:
                messagebox.showerror("Error", "Service not found.")

        ttk.Button(retrieve_window, text="Retrieve", command=show_password).grid(column=0, row=1, columnspan=2, pady=10)

    def encrypt_file_gui(self):
        """
        Opens a dialog to select and encrypt a file.
        """
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "File does not exist.")
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            encrypted_data = fernet.encrypt(data)
            encrypted_file_path = file_path + '.encrypted'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("Success", f"File encrypted and saved as '{encrypted_file_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file_gui(self):
        """
        Opens a dialog to select and decrypt a file.
        """
        file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.encrypted")])
        if not file_path:
            return
        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "File does not exist.")
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.key)
            decrypted_data = fernet.decrypt(data)
            decrypted_file_path = file_path.replace('.encrypted', '.decrypted')
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", f"File decrypted and saved as '{decrypted_file_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def backup_data(self):
        """
        Backs up the passwords data, salt, encrypted symmetric key, and RSA key files to a selected directory.
        """
        if not self.logged_in:
            messagebox.showerror("Error", "You must be logged in to perform a backup. Look for reset script only you know where you found this")
            return

        backup_dir = filedialog.askdirectory(title="Select Backup Directory")
        if not backup_dir:
            return

        try:
            # Backup passwords.json
            if os.path.exists(DATA_FILE):
                shutil.copy(DATA_FILE, os.path.join(backup_dir, 'passwords_backup.json'))

            # Backup salt from keyring
            stored_salt = keyring.get_password(SERVICE_NAME, 'salt')
            if stored_salt:
                with open(os.path.join(backup_dir, 'salt_backup.txt'), 'w') as f:
                    f.write(stored_salt)

            # Backup encrypted symmetric key
            encrypted_symmetric_key = keyring.get_password(SERVICE_NAME, 'encrypted_symmetric_key')
            if encrypted_symmetric_key:
                with open(os.path.join(backup_dir, 'encrypted_symmetric_key.txt'), 'w') as f:
                    f.write(encrypted_symmetric_key)

            # Backup 2FA secret
            encrypted_2fa_secret = keyring.get_password(SERVICE_NAME, '2fa_secret')
            if encrypted_2fa_secret:
                with open(os.path.join(backup_dir, '2fa_secret_backup.txt'), 'w') as f:
                    f.write(encrypted_2fa_secret)

            # Backup RSA key files
            private_key_enc = os.path.join(KEY_DIRECTORY, 'private_key.pem.enc')
            public_key_enc = os.path.join(KEY_DIRECTORY, 'public_key.pem.enc')
            if os.path.exists(private_key_enc):
                shutil.copy(private_key_enc, os.path.join(backup_dir, 'private_key_backup.pem.enc'))
            if os.path.exists(public_key_enc):
                shutil.copy(public_key_enc, os.path.join(backup_dir, 'public_key_backup.pem.enc'))

            messagebox.showinfo("Success", "Backup completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {e}")

    def restore_data(self):
        """
        Restores the passwords data, salt, encrypted symmetric key, and RSA key files from a selected directory.
        """
        if not self.logged_in:
            messagebox.showerror("Error", "You must be logged in to perform a recovery.")
            return

        backup_dir = filedialog.askdirectory(title="Select Backup Directory")
        if not backup_dir:
            return

        try:
            # Restore passwords.json
            backup_passwords = os.path.join(backup_dir, 'passwords_backup.json')
            if os.path.exists(backup_passwords):
                shutil.copy(backup_passwords, DATA_FILE)

            # Restore salt
            backup_salt = os.path.join(backup_dir, 'salt_backup.txt')
            if os.path.exists(backup_salt):
                with open(backup_salt, 'r') as f:
                    salt = f.read()
                keyring.set_password(SERVICE_NAME, 'salt', salt)

            # Restore encrypted symmetric key
            backup_encrypted_key = os.path.join(backup_dir, 'encrypted_symmetric_key.txt')
            if os.path.exists(backup_encrypted_key):
                with open(backup_encrypted_key, 'r') as f:
                    encrypted_symmetric_key = f.read()
                keyring.set_password(SERVICE_NAME, 'encrypted_symmetric_key', encrypted_symmetric_key)

            # Restore 2FA secret
            backup_2fa_secret = os.path.join(backup_dir, '2fa_secret_backup.txt')
            if os.path.exists(backup_2fa_secret):
                with open(backup_2fa_secret, 'r') as f:
                    encrypted_2fa_secret = f.read()
                keyring.set_password(SERVICE_NAME, '2fa_secret', encrypted_2fa_secret)

            # Restore RSA key files
            backup_private_key = os.path.join(backup_dir, 'private_key_backup.pem.enc')
            backup_public_key = os.path.join(backup_dir, 'public_key_backup.pem.enc')
            if os.path.exists(backup_private_key):
                shutil.copy(backup_private_key, os.path.join(KEY_DIRECTORY, 'private_key.pem.enc'))
            if os.path.exists(backup_public_key):
                shutil.copy(backup_public_key, os.path.join(KEY_DIRECTORY, 'public_key.pem.enc'))

            messagebox.showinfo("Success", "Recovery completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Recovery failed: {e}")

    def reset_password_manager_gui(self):
        """
        Resets the password manager by deleting all stored credentials and data files.
        WARNING: This will erase all stored passwords and encrypted files.
        """
        if not self.logged_in:
            messagebox.showerror("Error", "You must be logged in to reset the Password Manager.")
            return

        confirm = messagebox.askyesno("Confirm Reset", "Are you sure you want to reset the Password Manager? This will erase all stored data.")
        if confirm:
            try:
                # Delete all relevant keyring entries
                keys_to_delete = [
                    'master_password',
                    'salt',
                    'encrypted_symmetric_key',
                    '2fa_secret'  # Added to delete 2FA secret
                ]
                for key in keys_to_delete:
                    try:
                        keyring.delete_password(SERVICE_NAME, key)
                        print_status(f"Deleted {key} from {SERVICE_NAME}.")
                    except keyring.errors.PasswordDeleteError:
                        print_status(f"{key} not found in {SERVICE_NAME}.")

                # Delete RSA key files
                private_key_enc = os.path.join(KEY_DIRECTORY, 'private_key.pem.enc')
                public_key_enc = os.path.join(KEY_DIRECTORY, 'public_key.pem.enc')
                if os.path.exists(private_key_enc):
                    os.remove(private_key_enc)
                    print_status(f"Deleted {private_key_enc}.")
                if os.path.exists(public_key_enc):
                    os.remove(public_key_enc)
                    print_status(f"Deleted {public_key_enc}.")

                # Delete the data file
                if os.path.exists(DATA_FILE):
                    os.remove(DATA_FILE)
                    print_status(f"Deleted {DATA_FILE}.")

                messagebox.showinfo("Success", "Password Manager has been reset. Please restart the application to set a new master password.")
                self.master.destroy()  # Close the application
            except Exception as e:
                messagebox.showerror("Error", f"Reset failed: {e}")

    def reset_master_password_gui(self):
        """
        Allows the user to reset the master password.
        WARNING: This will erase all stored data.
        """
        reset_confirm = messagebox.askyesno("Reset Master Password", "Forgot your master password?\n\n"
                                                                    "This is your only option to reset it, which will erase all your stored data.\n\n"
                                                                    "Do you want to proceed?")
        if not reset_confirm:
            return

        # Inform the user that resetting will erase all data
        proceed = messagebox.askyesno("Confirm Reset", "Resetting the master password will erase **all stored data**.\n\n"
                                                      "Are you sure you want to proceed?")
        if not proceed:
            return

        # Proceed to reset the password manager
        self.reset_password_manager_gui()

    def show_all_services_gui(self):
        """
        Handles the "Show All Services" button click.
        Prompts the user to re-authenticate and then displays all services in cleartext.
        """
        # Prompt for master password
        password = simpledialog.askstring("Re-authentication", "Enter your master password:", show='*')
        if not password:
            messagebox.showerror("Error", "Master password is required to view all services.")
            return

        try:
            # Initialize password manager with the entered password to verify
            temp_key = initialize_password_manager_gui(password)
            # If re-authentication is successful, proceed
            self.display_all_services()
        except Exception as e:
            messagebox.showerror("Error", f"Re-authentication failed: {e}")

    def display_all_services(self):
        """
        Displays all services in cleartext in a new window.
        """
        display_window = tk.Toplevel(self.master)
        display_window.title("All Services")

        ttk.Label(display_window, text="All Services:", font=('Helvetica', 12, 'bold')).pack(padx=10, pady=10)

        services_listbox = tk.Listbox(display_window, width=50)
        services_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for service in self.data.keys():
            services_listbox.insert(tk.END, service)

        ttk.Button(display_window, text="Close", command=display_window.destroy).pack(pady=10)

    def reauthenticate(self):
        """
        Optional: Implement additional re-authentication steps if needed.
        Currently handled within show_all_services_gui.
        """
        pass  # Placeholder for future enhancements

def main():
    """
    The main entry point of the application.
    """
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
