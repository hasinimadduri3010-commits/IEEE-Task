
import hashlib
import json
import os

DATABASE = "hashes.json"


# STEP 1: Calculate SHA-256 hash of a file
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# STEP 2: Load previously stored hashes
def load_hashes():
    if not os.path.exists(DATABASE):
        return {}

    try:
        with open(DATABASE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            print("Error: Hash database must contain a JSON object.")
            return None

        for path, hash_value in data.items():
            if not isinstance(path, str) or not isinstance(hash_value, str):
                print("Error: Hash database contains invalid data.")
                return None

        return data

    except json.JSONDecodeError:
        print("Error: Hash database contains invalid JSON.")
        return None

    except OSError as error:
        print(f"Error reading hash database: {error}")
        return None


# STEP 3: Save hashes to the JSON database
def save_hashes(hashes):
    try:
        with open(DATABASE, "w", encoding="utf-8") as file:
            json.dump(hashes, file, indent=4)

        return True

    except OSError as error:
        print(f"Error saving hash database: {error}")
        return False


# STEP 4: Validate the selected file
def validate_file(file_path):
    if not file_path:
        print("Error: No file path provided.")
        return None

    file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        print("Error: Path does not exist.")
        return None

    if not os.path.isfile(file_path):
        print("Error: Selected path is not a file.")
        return None

    if not os.access(file_path, os.R_OK):
        print("Error: File is not readable.")
        return None

    return file_path


# STEP 5: Register a file
def register_file(file_path, hashes):
    file_path = validate_file(file_path)

    if file_path is None:
        return

    if file_path in hashes:
        print("File is already registered.")
        return

    try:
        baseline_hash = calculate_sha256(file_path)

    except OSError as error:
        print(f"Could not read file: {error}")
        return

    hashes[file_path] = baseline_hash

    if not save_hashes(hashes):
        del hashes[file_path]
        return

    print("\nFile registered successfully!")
    print("File:", file_path)
    print("Baseline hash:", baseline_hash)


# STEP 6: Check file integrity
def check_file(file_path, hashes):
    file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        if file_path in hashes:
            print("\nWARNING: REGISTERED FILE IS MISSING!")
            print("File:", file_path)
        else:
            print("Error: Path does not exist.")
        return

    if not os.path.isfile(file_path):
        print("Error: Selected path is not a file.")
        return

    if file_path not in hashes:
        print("Error: File has not been registered.")
        return

    try:
        current_hash = calculate_sha256(file_path)

    except OSError as error:
        print(f"Could not read file: {error}")
        return

    baseline_hash = hashes[file_path]

    print("\nFile:", file_path)
    print("Baseline hash:", baseline_hash)
    print("Current hash: ", current_hash)

    if baseline_hash == current_hash:
        print("\nINTEGRITY VERIFIED")
        print("No changes detected.")

    else:
        print("\nWARNING: MODIFICATION DETECTED!")
        print("The file content has changed.")


# STEP 7: List registered files
def list_registered_files(hashes):
    print("\n===== REGISTERED FILES =====")

    if not hashes:
        print("No files are currently registered.")
        return

    for index, file_path in enumerate(hashes, start=1):
        print(f"\n{index}. {file_path}")

        if os.path.exists(file_path):
            print("Status: Available")
        else:
            print("Status: Missing")


# STEP 8: Main menu
def main():
    hashes = load_hashes()

    if hashes is None:
        print("Unable to start File Integrity Monitor.")
        return

    while True:
        print("\n===== FILE INTEGRITY MONITOR =====")
        print("1. Register a new file")
        print("2. Check file integrity")
        print("3. List registered files")
        print("4. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            file_path = input("Enter the complete file path: ").strip()
            register_file(file_path, hashes)

        elif choice == "2":
            file_path = input("Enter the complete file path: ").strip()
            check_file(file_path, hashes)

        elif choice == "3":
            list_registered_files(hashes)

        elif choice == "4":
            print("Exiting File Integrity Monitor...")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()




 
