
import hashlib
import hmac
import json
import os
import secrets
import time
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ==========================================
# 1. CONFIGURATION
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(BASE_DIR, "hashes.json")
SIGNATURE_FILE = os.path.join(BASE_DIR, "hashes.hmac")
LOG_FILE = os.path.join(BASE_DIR, "security_log.txt")

KEY_DIR = os.path.join(
    os.path.expanduser("~"),
    ".file_integrity_monitor"
)

KEY_FILE = os.path.join(KEY_DIR, "secret.key")


# ==========================================
# 2. SECURITY EVENT LOGGING
# ==========================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


def log_event(event_type, message):

    if event_type == "WARNING":
        logging.warning(message)

    elif event_type == "ERROR":
        logging.error(message)

    else:
        logging.info(message)


# ==========================================
# 3. SECRET KEY MANAGEMENT
# ==========================================

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

    print("New secret key generated.")
    log_event("INFO", "New HMAC secret key generated.")

    return key


# ==========================================
# 4. SHA-256 FILE HASHING
# ==========================================

def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ==========================================
# 5. HMAC DATABASE AUTHENTICATION
# ==========================================

def generate_database_signature(hashes, key):

    database_data = json.dumps(
        hashes,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(
        key,
        database_data,
        hashlib.sha256
    ).hexdigest()


def verify_database_signature(hashes, key):

    if not os.path.exists(SIGNATURE_FILE):

        print("WARNING: Database signature is missing!")
        log_event(
            "WARNING",
            "Database signature missing."
        )

        return False

    try:

        with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
            stored_signature = file.read().strip()

        expected_signature = generate_database_signature(
            hashes, key
        )

        if hmac.compare_digest(
            stored_signature,
            expected_signature
        ):

            print("Database integrity verified.")
            log_event(
                "INFO",
                "Database integrity verification successful."
            )

            return True

        print("WARNING: DATABASE TAMPERING DETECTED!")

        log_event(
            "WARNING",
            "DATABASE TAMPERING DETECTED. Signature mismatch."
        )

        return False

    except OSError as error:

        print(f"Error verifying database signature: {error}")

        log_event(
            "ERROR",
            f"Database verification error: {error}"
        )

        return False


# ==========================================
# 6. DATABASE MANAGEMENT
# ==========================================

def load_hashes():

    if not os.path.exists(DATABASE):
        return {}

    try:

        with open(DATABASE, "r", encoding="utf-8") as file:
            hashes = json.load(file)

        if not isinstance(hashes, dict):
            raise ValueError("Database must contain a JSON object.")

        for file_path, hash_value in hashes.items():

            if not isinstance(file_path, str):
                raise ValueError("Invalid file path.")

            if not isinstance(hash_value, str):
                raise ValueError("Invalid hash value.")

            if len(hash_value) != 64:
                raise ValueError("Invalid SHA-256 hash length.")

            int(hash_value, 16)

        return hashes

    except (OSError, json.JSONDecodeError, ValueError) as error:

        print(f"Database loading error: {error}")

        log_event(
            "ERROR",
            f"Database loading failed: {error}"
        )

        raise


def save_hashes(hashes, key):

    database_temp = DATABASE + ".tmp"
    signature_temp = SIGNATURE_FILE + ".tmp"

    try:

        signature = generate_database_signature(
            hashes, key
        )

        with open(database_temp, "w", encoding="utf-8") as file:
            json.dump(hashes, file, indent=4)

        with open(signature_temp, "w", encoding="utf-8") as file:
            file.write(signature)

        os.replace(database_temp, DATABASE)
        os.replace(signature_temp, SIGNATURE_FILE)

        log_event(
            "INFO",
            "File registration database updated and signed."
        )

        return True

    except OSError as error:

        print(f"Error saving database: {error}")

        log_event(
            "ERROR",
            f"Database save failed: {error}"
        )

        for temp_file in (database_temp, signature_temp):

            if os.path.exists(temp_file):
                os.remove(temp_file)

        return False


def initialize_database(hashes, key):

    if os.path.exists(DATABASE):

        if os.path.exists(SIGNATURE_FILE):

            if not verify_database_signature(hashes, key):
                return False

        else:

            print("Existing database has no signature.")
            print("Review its contents before trusting it.")

            choice = input(
                "Do you trust this database and want to sign it? (yes/no): "
            ).strip().lower()

            if choice != "yes":

                print("Database was not trusted.")

                log_event(
                    "WARNING",
                    "User declined to trust unsigned database."
                )

                return False

            if not save_hashes(hashes, key):
                return False

            print("Existing database successfully signed.")

            log_event(
                "INFO",
                "Previously unsigned database was signed after user approval."
            )

    else:

        if not save_hashes(hashes, key):
            return False

        print("New database initialized.")

    return True


# ==========================================
# 7. FILE VALIDATION
# ==========================================

def validate_file(file_path):

    if not file_path:

        print("Error: File path cannot be empty.")
        return None

    file_path = os.path.abspath(
        os.path.normpath(
            file_path.strip().strip('"')
        )
    )

    if not os.path.exists(file_path):

        print("Error: File does not exist.")
        return None

    if not os.path.isfile(file_path):

        print("Error: Path is not a regular file.")
        return None

    if not os.access(file_path, os.R_OK):

        print("Error: File is not readable.")
        return None

    return os.path.normcase(file_path)


# ==========================================
# 8. REGISTER A NEW FILE
# ==========================================

def register_file(file_path, hashes, key):

    file_path = validate_file(file_path)

    if not file_path:
        return

    if file_path in hashes:

        print("File is already registered.")
        return

    try:

        file_hash = calculate_sha256(file_path)

        updated_hashes = hashes.copy()
        updated_hashes[file_path] = file_hash

        if save_hashes(updated_hashes, key):

            hashes.clear()
            hashes.update(updated_hashes)

            print("\nFile successfully registered!")
            print(f"File: {file_path}")
            print(f"SHA-256: {file_hash}")

            log_event(
                "INFO",
                f"FILE REGISTERED | {file_path}"
            )

    except OSError as error:

        print(f"Error registering file: {error}")

        log_event(
            "ERROR",
            f"File registration failed | {file_path} | {error}"
        )


# ==========================================
# 9. MANUAL INTEGRITY CHECK
# ==========================================

def check_file(file_path, hashes):

    file_path = validate_file(file_path)

    if not file_path:
        return

    if file_path not in hashes:

        print("File is not registered.")

        log_event(
            "WARNING",
            f"Unregistered file check attempted | {file_path}"
        )

        return

    try:

        current_hash = calculate_sha256(file_path)
        original_hash = hashes[file_path]

        print("\nOriginal SHA-256:", original_hash)
        print("Current SHA-256: ", current_hash)

        if hmac.compare_digest(
            current_hash,
            original_hash
        ):

            print("\nINTEGRITY VERIFIED: File is unchanged.")

            log_event(
                "INFO",
                f"INTEGRITY VERIFIED | {file_path}"
            )

        else:

            print("\nWARNING: FILE MODIFICATION DETECTED!")

            log_event(
                "WARNING",
                f"FILE MODIFICATION DETECTED | {file_path}"
            )

    except OSError as error:

        print(f"Error checking file: {error}")

        log_event(
            "ERROR",
            f"File integrity check failed | {file_path} | {error}"
        )


# ==========================================
# 10. LIST REGISTERED FILES
# ==========================================

def list_registered_files(hashes):

    if not hashes:

        print("No files registered.")
        return

    print("\n===== REGISTERED FILES =====")

    for index, file_path in enumerate(hashes, start=1):

        print(f"\n{index}. {file_path}")

        if os.path.exists(file_path):
            print("   Status: Available")

        else:
            print("   Status: Missing")


# ==========================================
# 11. WATCHDOG EVENT HANDLER
# ==========================================

class IntegrityEventHandler(FileSystemEventHandler):

    def __init__(self, hashes):

        self.hashes = hashes

    def get_registered_path(self, path):

        normalized_path = os.path.normcase(
            os.path.abspath(path)
        )

        for registered_path in self.hashes:

            if normalized_path == os.path.normcase(
                os.path.abspath(registered_path)
            ):

                return registered_path

        return None

    def on_modified(self, event):

        if event.is_directory:
            return

        registered_path = self.get_registered_path(
            event.src_path
        )

        if registered_path:

            print("\n[ALERT] Registered file modified!")
            print(f"File: {event.src_path}")

            try:

                current_hash = calculate_sha256(
                    event.src_path
                )

                original_hash = self.hashes[registered_path]

                if hmac.compare_digest(
                    current_hash,
                    original_hash
                ):

                    print("Integrity verified. Content unchanged.")

                else:

                    print("WARNING: FILE MODIFICATION DETECTED!")

                    log_event(
                        "WARNING",
                        f"FILE MODIFIED | {event.src_path} | HASH MISMATCH"
                    )

            except OSError as error:

                print(f"Unable to check file: {error}")

                log_event(
                    "ERROR",
                    f"Unable to hash modified file | {event.src_path} | {error}"
                )

    def on_deleted(self, event):

        if event.is_directory:
            return

        registered_path = self.get_registered_path(
            event.src_path
        )

        if registered_path:

            print("\n[ALERT] Registered file deleted!")
            print(f"File: {event.src_path}")

            log_event(
                "WARNING",
                f"FILE DELETED | {event.src_path}"
            )

    def on_created(self, event):

        if event.is_directory:
            return

        print(f"\n[EVENT] New file created: {event.src_path}")

        log_event(
            "INFO",
            f"FILE CREATED | {event.src_path}"
        )

    def on_moved(self, event):

        if event.is_directory:
            return

        registered_path = self.get_registered_path(
            event.src_path
        )

        if registered_path:

            print("\n[ALERT] Registered file moved or replaced!")
            print(f"Old path: {event.src_path}")
            print(f"New path: {event.dest_path}")

            log_event(
                "WARNING",
                f"REGISTERED FILE MOVED | {event.src_path} -> {event.dest_path}"
            )


# ==========================================
# 12. CONTINUOUS MONITORING
# ==========================================

def start_monitoring(hashes):

    if not hashes:

        print("No registered files available to monitor.")
        return

    monitored_directories = set()

    for file_path in hashes:

        if os.path.isfile(file_path):

            directory = os.path.dirname(
                os.path.abspath(file_path)
            )

            monitored_directories.add(directory)

    if not monitored_directories:

        print("No existing registered files found.")
        return

    event_handler = IntegrityEventHandler(hashes)
    observer = Observer()

    for directory in monitored_directories:

        observer.schedule(
            event_handler,
            directory,
            recursive=False
        )

    try:

        observer.start()

        print("\n===== CONTINUOUS MONITORING =====")
        print("Monitoring registered file directories.")
        print("Press CTRL+C to stop monitoring.")

        log_event(
            "INFO",
            "CONTINUOUS MONITORING STARTED"
        )

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print("\nStopping continuous monitoring...")

    finally:

        observer.stop()
        observer.join()

        print("Monitoring stopped.")

        log_event(
            "INFO",
            "CONTINUOUS MONITORING STOPPED"
        )


# ==========================================
# 13. MAIN MENU
# ==========================================

def main():

    try:

        key = load_or_create_secret_key()

        hashes = load_hashes()

        if not initialize_database(hashes, key):

            print("Monitoring has been stopped for safety.")
            return

    except (OSError, ValueError, RuntimeError) as error:

        print(f"Startup error: {error}")

        log_event(
            "ERROR",
            f"PROGRAM STARTUP FAILED | {error}"
        )

        return

    while True:

        print("\n===== FILE INTEGRITY MONITOR =====")
        print("1. Register a new file")
        print("2. Check file integrity")
        print("3. List registered files")
        print("4. Start continuous monitoring")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":

            file_path = input("Enter file path: ")

            register_file(
                file_path,
                hashes,
                key
            )

        elif choice == "2":

            file_path = input("Enter file path: ")

            check_file(
                file_path,
                hashes
            )

        elif choice == "3":

            list_registered_files(hashes)

        elif choice == "4":

            start_monitoring(hashes)

        elif choice == "5":

            print("Exiting File Integrity Monitor.")

            log_event(
                "INFO",
                "PROGRAM EXITED"
            )

            break

        else:

            print("Invalid choice. Please try again.")


# ==========================================
# 14. PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()
