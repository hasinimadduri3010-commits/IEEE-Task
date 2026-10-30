import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import logging
from datetime import datetime


# ============================================================
# 1. CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(BASE_DIR, "hashes.json")
SIGNATURE_FILE = os.path.join(BASE_DIR, "hashes.hmac")
LOG_FILE = os.path.join(BASE_DIR, "security_log.txt")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
MONITOR_SCRIPT = os.path.join(BASE_DIR, "monitor.py")

KEY_DIR = os.path.join(os.path.expanduser("~"), ".file_integrity_monitor")
KEY_FILE = os.path.join(KEY_DIR, "secret.key")


# ============================================================
# 2. TERMINAL COLOURS
# ============================================================

PURPLE = "\033[95m"
RED = "\033[91m"
GREEN = "\033[92m"
ORANGE = "\033[38;5;208m"
WHITE = "\033[97m"
RESET = "\033[0m"

os.system("")   # enables ANSI colours on Windows


def success(message):
    print(f"{GREEN}{message}{RESET}")


def warning(message):
    print(f"{ORANGE}{message}{RESET}")


def alert(message):
    print(f"{RED}{message}{RESET}")


def heading(message):
    print(f"{PURPLE}{message}{RESET}")


def normal(message):
    print(f"{WHITE}{message}{RESET}")


# ============================================================
# 3. LOGGING (file only, so the menu stays clean)
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],
    force=True
)


def log_event(event_type, message):

    if event_type == "WARNING":
        logging.warning(message)
    elif event_type == "ERROR":
        logging.error(message)
    else:
        logging.info(message)


# ============================================================
# 4. SECRET KEY
# ============================================================

def load_or_create_secret_key():

    os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(KEY_FILE):

        with open(KEY_FILE, "rb") as file:
            key = file.read()

        if len(key) != 32:
            raise ValueError("Invalid secret key length.")

        return key

    key = secrets.token_bytes(32)

    with open(KEY_FILE, "xb") as file:
        file.write(key)

    try:
        os.chmod(KEY_FILE, 0o600)   # owner-only (no effect on Windows)
    except OSError:
        pass

    success("New secret key generated.")
    log_event("INFO", "New HMAC secret key generated.")

    return key


# ============================================================
# 5. HASHING + HMAC
# ============================================================

def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(65536)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def generate_database_signature(hashes, key):

    data = json.dumps(
        hashes,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_database_signature(hashes, key):

    if not os.path.exists(SIGNATURE_FILE):
        alert("DATABASE SIGNATURE MISSING!")
        log_event("ERROR", "Database signature is missing.")
        return False

    try:

        with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
            stored = file.read().strip()

        expected = generate_database_signature(hashes, key)

        if hmac.compare_digest(stored, expected):
            success("DATABASE INTEGRITY VERIFIED.")
            log_event("INFO", "Database signature verification successful.")
            return True

        alert("DATABASE TAMPERING DETECTED!")
        log_event("ERROR", "Database signature mismatch. Possible tampering.")
        return False

    except OSError as error:
        alert(f"Database verification error: {error}")
        log_event("ERROR", str(error))
        return False


# ============================================================
# 6. DATABASE
# ============================================================

def load_hashes():

    if not os.path.exists(DATABASE):
        return {}

    try:

        with open(DATABASE, "r", encoding="utf-8") as file:
            hashes = json.load(file)

        if not isinstance(hashes, dict):
            raise ValueError("Database must contain a JSON object.")

        for path, value in hashes.items():

            if not isinstance(path, str) or not isinstance(value, str):
                raise ValueError("Invalid database entry.")

            if len(value) != 64:
                raise ValueError("Invalid SHA-256 hash length.")

            int(value, 16)

        return hashes

    except (OSError, json.JSONDecodeError, ValueError) as error:
        alert(f"Database loading failed: {error}")
        log_event("ERROR", f"Database loading failed: {error}")
        raise


def save_hashes(hashes, key):

    database_temp = DATABASE + ".tmp"
    signature_temp = SIGNATURE_FILE + ".tmp"

    try:

        signature = generate_database_signature(hashes, key)

        with open(database_temp, "w", encoding="utf-8") as file:
            json.dump(hashes, file, indent=4)

        with open(signature_temp, "w", encoding="utf-8") as file:
            file.write(signature)

        os.replace(database_temp, DATABASE)
        os.replace(signature_temp, SIGNATURE_FILE)

        log_event("INFO", "Database updated and signed.")
        return True

    except OSError as error:

        alert(f"Database saving failed: {error}")
        log_event("ERROR", f"Database saving failed: {error}")

        for temp in (database_temp, signature_temp):
            if os.path.exists(temp):
                try:
                    os.remove(temp)
                except OSError:
                    pass

        return False


def initialize_database(hashes, key):

    if os.path.exists(DATABASE):

        if os.path.exists(SIGNATURE_FILE):

            if not verify_database_signature(hashes, key):
                return False

        else:

            warning("Existing database has no signature.")

            choice = input(
                "Do you trust this database and want to sign it? (yes/no): "
            ).strip().lower()

            if choice != "yes":
                alert("Database was not trusted.")
                log_event("WARNING", "User declined to trust unsigned database.")
                return False

            if not save_hashes(hashes, key):
                return False

            success("Existing database signed.")

    else:

        if not save_hashes(hashes, key):
            return False

        success("New database initialized.")

    return True


# ============================================================
# 7. FILE VALIDATION
# ============================================================

def validate_file(file_path, must_exist=True):

    if not file_path or not file_path.strip():
        alert("File path cannot be empty.")
        return None

    file_path = os.path.abspath(
        os.path.normpath(file_path.strip().strip('"'))
    )

    if must_exist:

        if not os.path.exists(file_path):
            alert("File does not exist.")
            return None

        if not os.path.isfile(file_path):
            alert("Path is not a regular file.")
            return None

        if not os.access(file_path, os.R_OK):
            alert("File is not readable.")
            return None

    return os.path.normcase(file_path)


# ============================================================
# 8. BACKUPS
# ============================================================

def backup_prefix(file_path):
    """Unique per full path, so same-named files never collide."""

    tag = hashlib.sha256(file_path.encode("utf-8")).hexdigest()[:8]
    return f"{os.path.basename(file_path)}.{tag}."


def create_backup(file_path):

    try:

        os.makedirs(BACKUP_DIR, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = os.path.join(
            BACKUP_DIR, backup_prefix(file_path) + timestamp
        )

        shutil.copy2(file_path, backup_path)

        if calculate_sha256(file_path) != calculate_sha256(backup_path):
            os.remove(backup_path)
            alert("Backup verification failed!")
            log_event("ERROR", f"Backup verification failed | {file_path}")
            return None

        success("Verified backup created.")
        normal(f"Backup location: {backup_path}")
        log_event("INFO", f"BACKUP CREATED | {file_path} | {backup_path}")

        return backup_path

    except OSError as error:
        alert(f"Backup failed: {error}")
        log_event("ERROR", f"Backup failed: {error}")
        return None


def restore_backup(file_path, hashes):

    # The file may be deleted, so it does not have to exist.
    file_path = validate_file(file_path, must_exist=False)

    if not file_path:
        return

    if file_path not in hashes:
        warning("File is not registered.")
        return

    if not os.path.isdir(BACKUP_DIR):
        warning("No backup directory exists.")
        return

    prefix = backup_prefix(file_path)

    candidates = [
        os.path.join(BACKUP_DIR, name)
        for name in os.listdir(BACKUP_DIR)
        if name.startswith(prefix)
    ]

    candidates.sort(key=os.path.getmtime, reverse=True)

    # Only restore a backup that matches the registered baseline.
    backup_path = None

    for candidate in candidates:
        try:
            if calculate_sha256(candidate) == hashes[file_path]:
                backup_path = candidate
                break
        except OSError:
            continue

    if not backup_path:
        warning("No backup matches the registered baseline.")
        return

    try:

        normal(f"\nBackup:  {backup_path}")
        normal(f"SHA-256: {hashes[file_path]}")

        confirmation = input(
            "Restore this backup and overwrite the current file? (yes/no): "
        ).strip().lower()

        if confirmation != "yes":
            warning("Restore cancelled.")
            log_event("WARNING", f"Restore cancelled | {file_path}")
            return

        previous_copy = None

        if os.path.isfile(file_path):
            previous_copy = file_path + ".pre_restore"
            shutil.copy2(file_path, previous_copy)

        shutil.copy2(backup_path, file_path)

        if calculate_sha256(file_path) != hashes[file_path]:

            if previous_copy:
                shutil.copy2(previous_copy, file_path)

            alert("Restore verification failed.")
            log_event("ERROR", f"Restore verification failed | {file_path}")
            return

        success("FILE RESTORED AND VERIFIED.")
        log_event("INFO", f"FILE RESTORED | {file_path} | {backup_path}")

    except OSError as error:
        alert(f"Restore failed: {error}")
        log_event("ERROR", f"Restore failed: {error}")


# ============================================================
# 9. REGISTER / CHECK / LIST / UPDATE / REMOVE
# ============================================================

def register_file(file_path, hashes, key):

    file_path = validate_file(file_path)

    if not file_path:
        return

    if file_path in hashes:
        warning("File is already registered.")
        return

    try:

        file_hash = calculate_sha256(file_path)

        updated = hashes.copy()
        updated[file_path] = file_hash

        if save_hashes(updated, key):

            hashes.clear()
            hashes.update(updated)

            success("\nFILE SUCCESSFULLY REGISTERED!")
            normal(f"File: {file_path}")
            normal(f"SHA-256: {file_hash}")

            log_event("INFO", f"FILE REGISTERED | {file_path}")

            create_backup(file_path)

    except OSError as error:
        alert(f"Registration failed: {error}")
        log_event("ERROR", f"Registration failed | {error}")


def check_file(file_path, hashes):

    file_path = validate_file(file_path)

    if not file_path:
        return

    if file_path not in hashes:
        warning("File is not registered.")
        log_event("WARNING", f"Unregistered file check | {file_path}")
        return

    try:

        current = calculate_sha256(file_path)
        original = hashes[file_path]

        normal(f"\nOriginal SHA-256: {original}")
        normal(f"Current SHA-256:  {current}")

        if hmac.compare_digest(current, original):
            success("\nINTEGRITY VERIFIED: File is unchanged.")
            log_event("INFO", f"INTEGRITY VERIFIED | {file_path}")

        else:
            alert("\nFILE MODIFICATION DETECTED!")
            log_event("WARNING", f"FILE MODIFICATION DETECTED | {file_path}")
            warning("Use option 5 to restore the verified backup.")

    except OSError as error:
        alert(f"Integrity check failed: {error}")
        log_event("ERROR", f"Integrity check failed | {file_path} | {error}")


def list_registered_files(hashes):

    if not hashes:
        warning("No files registered.")
        return

    heading("\n========== REGISTERED FILES ==========")

    for index, file_path in enumerate(hashes, start=1):

        normal(f"\n{index}. {file_path}")

        if os.path.exists(file_path):
            success("   Status: Available")
        else:
            alert("   Status: Missing")


def update_baseline(file_path, hashes, key):
    """Accept a legitimate edit as the new trusted version."""

    file_path = validate_file(file_path)

    if not file_path:
        return

    if file_path not in hashes:
        warning("File is not registered.")
        return

    try:

        new_hash = calculate_sha256(file_path)

        if new_hash == hashes[file_path]:
            normal("File already matches its baseline.")
            return

        normal(f"\nOld baseline: {hashes[file_path]}")
        normal(f"New baseline: {new_hash}")

        confirmation = input(
            "Trust the current file as the new baseline? (yes/no): "
        ).strip().lower()

        if confirmation != "yes":
            warning("Baseline update cancelled.")
            return

        updated = hashes.copy()
        updated[file_path] = new_hash

        if save_hashes(updated, key):

            hashes.clear()
            hashes.update(updated)

            success("BASELINE UPDATED.")
            log_event("INFO", f"BASELINE UPDATED | {file_path}")

            create_backup(file_path)

    except OSError as error:
        alert(f"Baseline update failed: {error}")
        log_event("ERROR", f"Baseline update failed | {error}")


def unregister_file(file_path, hashes, key):

    file_path = validate_file(file_path, must_exist=False)

    if not file_path:
        return

    if file_path not in hashes:
        warning("File is not registered.")
        return

    confirmation = input(
        "Stop monitoring this file? (yes/no): "
    ).strip().lower()

    if confirmation != "yes":
        warning("Cancelled.")
        return

    updated = hashes.copy()
    del updated[file_path]

    if save_hashes(updated, key):

        hashes.clear()
        hashes.update(updated)

        success("FILE UNREGISTERED.")
        log_event("INFO", f"FILE UNREGISTERED | {file_path}")


# ============================================================
# 10. LIVE DASHBOARD (runs monitor.py)
# ============================================================

def start_monitoring():

    if not os.path.isfile(MONITOR_SCRIPT):
        alert(f"monitor.py not found next to hash.py:\n{MONITOR_SCRIPT}")
        return

    try:
        subprocess.run([sys.executable, MONITOR_SCRIPT])
    except KeyboardInterrupt:
        pass

    success("\nBack to the main menu.")


# ============================================================
# 11. MAIN MENU
# ============================================================

def main():

    print("\n")

    heading("========================================")
    heading("       FILE INTEGRITY MONITOR")
    heading("========================================")

    try:

        key = load_or_create_secret_key()
        hashes = load_hashes()

        if not initialize_database(hashes, key):
            alert("Monitoring has been stopped for safety.")
            return

    except (OSError, ValueError, json.JSONDecodeError) as error:
        alert(f"Startup failed: {error}")
        log_event("ERROR", f"Startup failed: {error}")
        return

    while True:

        print("\n")
        heading("========== MAIN MENU ==========")

        normal("1. Register a new file")
        normal("2. Check file integrity")
        normal("3. List registered files")
        normal("4. Start live dashboard (2-second scanning)")
        normal("5. Restore latest verified backup")
        normal("6. Update baseline (trust an edited file)")
        normal("7. Unregister a file")
        normal("8. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            register_file(input("Enter file path: "), hashes, key)

        elif choice == "2":
            check_file(input("Enter file path: "), hashes)

        elif choice == "3":
            list_registered_files(hashes)

        elif choice == "4":
            start_monitoring()

        elif choice == "5":
            restore_backup(input("Enter file path to restore: "), hashes)

        elif choice == "6":
            update_baseline(input("Enter file path: "), hashes, key)

        elif choice == "7":
            unregister_file(input("Enter file path: "), hashes, key)

        elif choice == "8":
            success("Exiting File Integrity Monitor.")
            log_event("INFO", "Application exited.")
            break

        else:
            warning("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()