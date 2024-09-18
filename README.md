
## Overview
This Python script is a multi-OS password manager with file encryption and decryption. It is secure, user-friendly, and designed to work across multiple desktop operating systems. With built-in Two-Factor Authentication (2FA), it ensures that your sensitive information remains protected at all times. Whether you're using Windows, macOS, or Linux, this application provides a consistent and reliable way to manage your passwords and secure your important files.

## Key Features

### Cross-Platform Support
- Works smoothly on **Windows**, **macOS**, and **Linux**, ensuring you have access to your passwords and files no matter which desktop OS you use.

### Two-Factor Authentication (2FA)
- Adds an extra layer of security by requiring a Time-based One-Time Password (TOTP) during login, protecting your account even if your master password is compromised.

### Secure Password Management
- Store, retrieve, and manage your passwords securely with encryption, ensuring that your credentials are always safe.

### File Encryption
- Easily encrypt and decrypt your important files, keeping your personal and professional documents protected from unauthorized access.

### Masked Service Names
- View your saved services in a masked format for added privacy, preventing onlookers from easily identifying the services you use.

### Re-authentication for Detailed Access
- Requires you to log in again to view full password details, ensuring that sensitive information remains protected.

### Backup & Recovery
- Safeguard your data by backing up your passwords, encryption keys, and RSA key files, and restore them whenever needed.

### User-Friendly Interface
- Built with **Tkinter**, offering an intuitive and easy-to-navigate graphical interface that makes managing your passwords and files straightforward.

## Detailed Functionality

With CrossPlatformPasswordManager, managing your passwords is both secure and straightforward. When you open the application, you'll see a list of all your saved services displayed in a masked format—only the first and last letters of each service name are visible, with asterisks in between (**G**********e** for Google). This way, anyone glancing at your screen can't easily see which services you use.

To view the full details of any service, like your username and password, you'll need to re-authenticate by entering your master password and completing the Two-Factor Authentication (2FA) step. This extra layer of security ensures that even if someone else has temporary access to your computer, they can't access your sensitive information without your permission.

## Why I Chose These Methods

When developing **CrossPlatformPasswordManager**, security and usability were my top priorities. Here's why I selected the specific encryption methods and tools:

### Fernet for Symmetric Encryption
- **Security**: Fernet provides AES 128-bit encryption in CBC mode with PKCS7 padding and HMAC for authentication. This combination ensures both the confidentiality and integrity of your data.
- **Simplicity**: Fernet handles many low-level details, making it easier to implement secure encryption without getting bogged down by complex cryptographic operations.

### RSA 2048-bit with OAEP Padding for Asymmetric Encryption
- **Strong Security**: RSA with a 2048-bit key size offers robust protection against brute-force attacks. OAEP padding with SHA256 enhances security by preventing certain types of cryptographic attacks.
- **Key Management**: Using RSA allows me to securely encrypt the symmetric key, ensuring that the key remains protected even if the encrypted symmetric key is accessed by unauthorized parties.

### Keyring for Secure Storage
- **System Integration**: The keyring library integrates with the native keychain services of **Windows**, **macOS**, and **Linux**, providing a secure and consistent way to store sensitive information across different operating systems.
- **Ease of Use**: By leveraging existing secure storage solutions, I avoid the complexities and potential pitfalls of implementing my own secure storage mechanisms.

### PyOTP for Two-Factor Authentication (2FA)
- **Enhanced Security**: Implementing TOTP-based 2FA adds an extra layer of protection, ensuring that even if your master password is compromised, unauthorized access is still prevented.
- **Compatibility**: PyOTP is widely supported by popular authenticator apps like Google Authenticator and Authy, making it easy for users to set up and use 2FA.

### Tkinter for the GUI
- **Cross-Platform Compatibility**: Tkinter is included with Python and works seamlessly across **Windows**, **macOS**, and **Linux**, ensuring a consistent user experience regardless of the operating system.
- **Lightweight and Easy to Use**: Tkinter allows for the creation of simple and intuitive interfaces without requiring additional dependencies, making the application accessible to a wider range of users.

## Encryption Details

### Symmetric Encryption
- **Algorithm**: Fernet (AES 128 in CBC mode with PKCS7 padding and HMAC for authentication).
- **Purpose**: Used for encrypting passwords and files, ensuring data confidentiality and integrity.
- **Key Derivation**: The symmetric key is derived from the master password hash and salt using PBKDF2HMAC with SHA256, performing 100,000 iterations to resist brute-force attacks.

### Asymmetric Encryption
- **Algorithm**: RSA with OAEP padding using SHA256.
- **Key Size**: 2048 bits.
- **Purpose**: Encrypts the symmetric key, adding an additional layer of security by protecting the key with asymmetric encryption.

## Key Storage

The application utilizes the **keyring** library to securely store critical credentials in the system's native keychain:

- **Master Password Hash**: Stored under the service name **CrossPlatformPasswordManager** with the key `master_password`. The hash is stored as a hexadecimal string.
- **Salt**: Stored as a base64-encoded string under the key `salt`.
- **Encrypted Symmetric Key**: Stored as a base64-encoded string under the key `encrypted_symmetric_key`.
- **2FA Secret**: Stored as an encrypted string under the key `2fa_secret`.

### Encrypted RSA Keys

All encryption keys are stored in the `keys` directory within the application folder. Although this is a regular directory, the keys themselves are encrypted using the symmetric key derived from your master password.

- **Private Key**: Stored as `keys/private_key.pem.enc`. This file contains your RSA private key encrypted with Fernet.
- **Public Key**: Stored as `keys/public_key.pem.enc`. Similarly, this file contains your RSA public key encrypted with Fernet.

### Best Practices
- **Secure File Permissions**: Ensure that the keys directory is not accessible to unauthorized users on your system. You can set appropriate file permissions to restrict access.
- **Regular Backups**: Backup your keys directory along with your data to prevent loss in case of system failure.

## Two-Factor Authentication (2FA) Implementation

- **Type**: Time-based One-Time Passwords (TOTP) via the pyotp library.
- **Setup**: During the initial setup, a TOTP secret is generated and displayed as a QR code using the `qrcode` and `Pillow` libraries. Users can scan this QR code with an authenticator app (e.g., Google Authenticator, Authy).
- **Verification**: Upon login, after entering the master password, users are prompted to enter the 6-digit code from their authenticator app. The application verifies this code to complete the authentication process.
- **Storage**: The 2FA secret is encrypted with the symmetric key and securely stored using keyring.

## Usage

### Initial Setup
- **Set Master Password**: Upon first launch, you'll be prompted to set a master password. Ensure it meets the strength requirements:
  - At least 8 characters.
  - Contains uppercase and lowercase letters.
  - Includes digits.
  - Contains special characters.
  
- **2FA Setup**: After setting the master password, a QR code will be displayed. Scan this with your preferred authenticator app to enable 2FA.

### Logging In
- **Enter Master Password**: On subsequent launches, enter your master password.
- **2FA Verification**: Enter the 6-digit code from your authenticator app to complete the login process.

### Managing Passwords
- **Add New Password**: Store new service credentials securely.
- **Retrieve Password**: Fetch and decrypt stored credentials.
- **Show All Services**: View a masked list of all stored services.

### File Encryption
- **Encrypt File**: Select a file to encrypt. The encrypted file will have an `.encrypted` extension.
- **Decrypt File**: Select an encrypted file to decrypt. The decrypted file will have a `.decrypted` extension.

### Backup & Recovery
- **Backup Data**: Backup your passwords, salts, encrypted keys, and RSA key files to a selected directory.
- **Restore Data**: Restore your data from a backup directory.
- **Reset Password Manager**: Reset the application, which will erase all stored data. Use this only if necessary.

- ## Installation

To run this, you'll need to install a few dependencies. Make sure you have Python installed, then run the following `pip` command to install all required libraries:

```bash
pip install cryptography keyring pyotp Pillow qrcode tk

