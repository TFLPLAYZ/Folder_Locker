import os
import shutil
import zipfile
import stat
import random
import string
import hashlib
import json
import argparse
import datetime
import pyotp
import qrcode
import getpass
from cryptography.fernet import Fernet

# Config
LOCK_METHODS = ["zip", "rename", "permission", "hiddenmove", "encrypt", "combo"]
LOCK_STATE_FILE = ".lock_state.json"
AUDIT_LOG_FILE = ".audit_log.txt.enc"
FERNET_KEY_FILE = ".audit_key.key"
TOTP_SECRET_FILE = ".totp_secret.txt"
PASSWORD_HASH = hashlib.sha256("1234".encode()).hexdigest()  # Change this in production


# =========================
# TOTP SETUP
# =========================

def get_totp():
    if not os.path.exists(TOTP_SECRET_FILE):
        secret = pyotp.random_base32()
        with open(TOTP_SECRET_FILE, 'w') as f:
            f.write(secret)
        print("Scan this QR code with your Authenticator app:")
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name="FolderLocker", issuer_name="SecureLocker")
        img = qrcode.make(uri)
        img.show()
    else:
        with open(TOTP_SECRET_FILE, 'r') as f:
            secret = f.read()
    return pyotp.TOTP(secret)

def verify_totp():
    totp = get_totp()
    code = input("Enter code from your Authenticator app: ").strip()
    return totp.verify(code)


# =========================
# ENCRYPTION UTILS
# =========================

def get_fernet():
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(FERNET_KEY_FILE, 'rb') as f:
            key = f.read()
    return Fernet(key)

def generate_random_name(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def zip_and_encrypt_folder(folder_path):
    zip_path = folder_path + ".zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, start=folder_path)
                zipf.write(full_path, arcname=arcname)
    shutil.rmtree(folder_path)
    return zip_path

def unzip_folder(zip_path):
    folder_path = zip_path.replace(".zip", "")
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(folder_path)
    os.remove(zip_path)
    return folder_path

def rename_folder(folder_path):
    new_name = generate_random_name()
    new_path = os.path.join(os.path.dirname(folder_path), new_name)
    os.rename(folder_path, new_path)
    return new_path

def restore_renamed_folder(current_path, original_path):
    os.rename(current_path, original_path)

def remove_permissions(folder_path):
    os.chmod(folder_path, 0)

def restore_permissions(folder_path):
    os.chmod(folder_path, stat.S_IRWXU)

def move_to_hidden_location(folder_path):
    hidden_base = os.path.join("C:\\ProgramData\\SystemCache")
    if not os.path.exists(hidden_base):
        os.makedirs(hidden_base)
    new_name = generate_random_name() + ".sys"
    new_path = os.path.join(hidden_base, new_name)
    shutil.move(folder_path, new_path)
    return new_path

def restore_moved_folder(current_path, original_path):
    shutil.move(current_path, original_path)

def encrypt_folder_contents(folder_path):
    fernet = get_fernet()
    manifest = {}
    log_lines = []

    for root, dirs, files in os.walk(folder_path, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()

                file_hash = hashlib.sha256(data).hexdigest()
                encrypted_data = fernet.encrypt(data)

                enc_path = file_path + '.enc'
                payload = {
                    "hash": file_hash,
                    "data": encrypted_data.decode()
                }

                with open(enc_path, 'w') as f:
                    json.dump(payload, f)

                os.remove(file_path)

                obf_name = generate_random_name()
                obf_path = os.path.join(root, obf_name)
                os.rename(enc_path, obf_path)
                manifest[obf_path] = file_path

                log_lines.append(f"[+] Encrypted file: {file_path} -> {obf_path}")
            except Exception as e:
                log_lines.append(f"[!] Failed to encrypt {file_path}: {e}")

        for name in dirs:
            dir_path = os.path.join(root, name)
            obf_name = generate_random_name()
            obf_path = os.path.join(root, obf_name)
            os.rename(dir_path, obf_path)
            manifest[obf_path] = dir_path
            log_lines.append(f"[+] Renamed folder: {dir_path} -> {obf_path}")

    manifest_data = json.dumps(manifest)
    encrypted_manifest = fernet.encrypt(manifest_data.encode())
    manifest_path = os.path.join(folder_path, ".manifest.enc")
    with open(manifest_path, 'wb') as f:
        f.write(encrypted_manifest)
    log_lines.append(f"[+] Encrypted and saved manifest: {manifest_path}")

    for line in log_lines:
        log_action(line)
        print(line)

    return True

def decrypt_folder_contents(folder_path):
    fernet = get_fernet()
    log_lines = []

    manifest_path = os.path.join(folder_path, ".manifest.enc")
    if not os.path.exists(manifest_path):
        print("[!] Manifest file not found. Cannot decrypt filenames.")
        return False

    try:
        with open(manifest_path, 'rb') as f:
            encrypted_manifest = f.read()
        manifest = json.loads(fernet.decrypt(encrypted_manifest).decode())
    except Exception as e:
        print(f"[!] Failed to load manifest: {e}")
        return False

    sorted_paths = sorted(manifest.items(), key=lambda x: x[0].count(os.sep), reverse=True)

    for obf_path, original_path in sorted_paths:
        try:
            if os.path.isfile(obf_path):
                with open(obf_path, 'r') as f:
                    payload = json.load(f)

                encrypted_data = payload.get("data")
                expected_hash = payload.get("hash")

                decrypted_data = fernet.decrypt(encrypted_data.encode())
                actual_hash = hashlib.sha256(decrypted_data).hexdigest()

                if actual_hash != expected_hash:
                    raise ValueError("Hash mismatch — possible tampering!")

                with open(original_path, 'wb') as f:
                    f.write(decrypted_data)

                os.remove(obf_path)
                log_lines.append(f"[+] Decrypted file: {obf_path} -> {original_path}")
            elif os.path.isdir(obf_path):
                os.rename(obf_path, original_path)
                log_lines.append(f"[+] Restored folder name: {obf_path} -> {original_path}")
        except Exception as e:
            log_lines.append(f"[!] Failed to decrypt {obf_path}: {e}")

    os.remove(manifest_path)
    log_lines.append(f"[+] Removed manifest: {manifest_path}")

    for line in log_lines:
        log_action(line)
        print(line)

    return True


# =========================
# LOGGING & STATE
# =========================

def log_action(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    fernet = get_fernet()
    encrypted = fernet.encrypt(full_message.encode())
    with open(AUDIT_LOG_FILE, 'ab') as f:
        f.write(encrypted + b"\n")

def decrypt_log():
    if not os.path.exists(AUDIT_LOG_FILE):
        print("No audit log found.")
        return
    fernet = get_fernet()
    with open(AUDIT_LOG_FILE, 'rb') as f:
        for line in f:
            try:
                decrypted = fernet.decrypt(line.strip())
                print(decrypted.decode())
            except Exception:
                print("[Error] Unable to decrypt line.")

def save_lock_state(lock_record):
    history = []
    if os.path.exists(LOCK_STATE_FILE):
        with open(LOCK_STATE_FILE, 'r') as f:
            history = json.load(f)
    history.append(lock_record)
    with open(LOCK_STATE_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def load_lock_state():
    if not os.path.exists(LOCK_STATE_FILE):
        return []
    with open(LOCK_STATE_FILE, 'r') as f:
        return json.load(f)

def write_lock_record(method, path, extra):
    save_lock_state({
        "method": method,
        "path": path,
        "extra": extra
    })
    log_action(f"LOCKED [{method.upper()}] -> {path}")

def remove_lock_record(index):
    states = load_lock_state()
    if 0 <= index < len(states):
        removed = states.pop(index)
        with open(LOCK_STATE_FILE, 'w') as f:
            json.dump(states, f, indent=2)
        log_action(f"REMOVED [{removed['method'].upper()}] -> {removed['path']}")
        print(f"Removed lock record: [{removed['method'].upper()}] -> {removed['path']}")
    else:
        print("Invalid index.")


# =========================
# LOCKING FUNCTIONS
# =========================

def lock_menu(folder=None, method=None):
    if not folder:
        folder = input("Enter folder path to lock: ").strip()
    if not method:
        print("Choose lock method:")
        print("1. ZIP + delete original")
        print("2. Rename/Hide folder")
        print("3. Remove access permissions")
        print("4. Move to hidden system directory")
        print("5. Encrypt files in folder")
        print("6. Encrypt then move to hidden system directory")
        choice = input("Enter choice (1-6): ").strip()
    else:
        choice = method

    if choice == "1" or method == "zip":
        zip_path = zip_and_encrypt_folder(folder)
        write_lock_record("zip", zip_path, None)
        print("Folder locked in zip.")
    elif choice == "2" or method == "rename":
        new_path = rename_folder(folder)
        write_lock_record("rename", new_path, folder)
        print(f"Folder renamed to obscure name: {new_path}")
    elif choice == "3" or method == "permission":
        remove_permissions(folder)
        write_lock_record("permission", folder, None)
        print("Permissions removed.")
    elif choice == "4" or method == "hiddenmove":
        new_path = move_to_hidden_location(folder)
        write_lock_record("hiddenmove", new_path, folder)
        print(f"Folder moved to hidden location: {new_path}")
    elif choice == "5" or method == "encrypt":
        encrypt_folder_contents(folder)
        write_lock_record("encrypt", folder, None)
        print("Folder contents encrypted.")
    elif choice == "6" or method == "combo":
        encrypt_folder_contents(folder)
        new_path = move_to_hidden_location(folder)
        write_lock_record("combo", new_path, folder)
        print(f"Folder encrypted and moved to hidden location: {new_path}")
    else:
        print("Invalid choice.")
        return

def unlock_menu():
    if not verify_totp():
        print("Invalid TOTP. Access denied.")
        return

    password = getpass.getpass("Enter password to unlock: ")
    if hashlib.sha256(password.encode()).hexdigest() != PASSWORD_HASH:
        print("Incorrect password.")
        return

    states = load_lock_state()
    if not states:
        print("No locked folders found.")
        return

    print("Select a folder to unlock:")
    for idx, state in enumerate(states):
        print(f"{idx + 1}. [{state['method'].upper()}] -> {state['path']}")

    selection = input("Enter number to unlock specific folder: ").strip()
    if not selection.isdigit():
        print("Invalid input.")
        return

    index = int(selection) - 1
    if not (0 <= index < len(states)):
        print("Invalid selection.")
        return

    state = states[index]
    method, path, extra = state["method"], state["path"], state["extra"]
    print(f"Unlocking [{method.upper()}]: {path}")

    if method == "combo":
        restore_moved_folder(path, extra)
        print(f"Folder moved back to original location: {extra}")
        decrypt_folder_contents(extra)
        print("Folder contents decrypted.")
    elif method == "zip":
        folder = unzip_folder(path)
        print(f"Unzipped folder: {folder}")
    elif method == "rename":
        restore_renamed_folder(path, extra)
        print(f"Folder renamed back to original: {extra}")
    elif method == "permission":
        restore_permissions(path)
        print("Permissions restored.")
    elif method == "hiddenmove":
        restore_moved_folder(path, extra)
        print(f"Folder moved back to original location: {extra}")
    elif method == "encrypt":
        decrypt_folder_contents(path)
        print("Folder contents decrypted.")
    else:
        print("Unknown lock method.")

    log_action(f"UNLOCKED [{method.upper()}] -> {path}")
    states.pop(index)

    with open(LOCK_STATE_FILE, 'w') as f:
        json.dump(states, f, indent=2)

def list_locked_folders():
    states = load_lock_state()
    if not states:
        print("No locked folders found.")
        return
    print("Locked folders:")
    for idx, state in enumerate(states):
        print(f"{idx + 1}. [{state['method'].upper()}] -> {state['path']}")

def main():
    parser = argparse.ArgumentParser(description="Folder Locker CLI")
    parser.add_argument('--lock', metavar='FOLDER', help='Lock a folder')
    parser.add_argument('--unlock', action='store_true', help='Unlock folders')
    parser.add_argument('--list', action='store_true', help='List all locked folders')
    parser.add_argument('--remove', type=int, metavar='INDEX', help='Remove lock entry by index')
    parser.add_argument('--decrypt-log', action='store_true', help='Decrypt and display audit log')
    parser.add_argument('--method', choices=LOCK_METHODS, help='Lock method')
    args = parser.parse_args()

    if args.lock:
        lock_menu(folder=args.lock, method=args.method)
    elif args.unlock:
        unlock_menu()
    elif args.list:
        list_locked_folders()
    elif args.remove is not None:
        remove_lock_record(args.remove - 1)
    elif args.decrypt_log:
        decrypt_log()
    else:
        print("1. Lock folder")
        print("2. Unlock folder")
        print("3. List locked folders")
        print("4. Remove lock record")
        print("5. Decrypt audit log")
        choice = input("Select option: ")
        if choice == "1":
            lock_menu()
        elif choice == "2":
            unlock_menu()
        elif choice == "3":
            list_locked_folders()
        elif choice == "4":
            index = int(input("Enter index to remove: ")) - 1
            remove_lock_record(index)
        elif choice == "5":
            decrypt_log()
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
    # Note: The script should be run with Python 3.6+ and requires the following packages:
    # pip install pyotp qrcode cryptography