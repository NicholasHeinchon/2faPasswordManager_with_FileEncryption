import keyring

# Constants
SERVICE_NAME = 'CrossPlatformPasswordManager'
CREDENTIAL_KEYS = [
    'master_password',
    'salt',
    'private_key',
    'public_key',
    'encrypted_symmetric_key'
]

def reset_password_manager():
    for key in CREDENTIAL_KEYS:
        try:
            keyring.delete_password(SERVICE_NAME, key)
            print(f"[INFO] Deleted {key} from {SERVICE_NAME}.")
        except keyring.errors.PasswordDeleteError:
            print(f"[WARNING] {key} not found in {SERVICE_NAME}.")

if __name__ == "__main__":
    confirm = input("Are you sure you want to reset the Password Manager? This will erase all stored data. (yes/no): ")
    if confirm.lower() == 'yes':
        reset_password_manager()
        print("Password Manager has been reset. You can now set a new master password.")
    else:
        print("Reset operation cancelled.")
