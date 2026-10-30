# File Integrity Monitor

## Overview
The File Integrity Monitor is a Python-based cybersecurity project designed to detect unauthorized or unexpected modifications to files.

It uses the SHA-256 cryptographic hashing algorithm to generate unique hash values for files. These values are stored as baseline records and compared against newly generated hashes to identify changes.

## Objectives
- Understand cryptographic hashing and file integrity.
- Generate SHA-256 hashes for files.
- Store baseline hashes persistently using JSON.
- Detect modifications through hash comparison.
- Handle invalid file paths and missing files.
- Monitor multiple registered files.

## Technologies Used
- **Python** – Core programming language.
- **Hashlib** – SHA-256 hash generation.
- **OS** – File handling, path validation and file operations.
- **JSON** – Persistent storage of baseline hashes.

## How It Works

The project follows these steps:

1. **File Selection:** The user provides the path of the file to be monitored.
2. **File Registration:** The program reads the file in binary mode and calculates its SHA-256 hash.
3. **Baseline Storage:** The generated hash is stored in `hashes.json`.
4. **Integrity Verification:** When requested, the program calculates the file's current hash.
5. **Hash Comparison:** The current hash is compared with the stored baseline.
6. **Result:** The program reports whether the file remains unchanged or has been modified.

## Features
- SHA-256 cryptographic hashing.
- Chunk-based file reading for memory efficiency.
- Persistent baseline storage.
- File registration and duplicate detection.
- File integrity verification.
- Modification detection.
- Missing-file detection.
- Registered-file listing.
- Basic error handling and path validation.

## Project Structure

```text
File-Integrity-Monitor/
│
├── hash.py
├── hashes.json
├── sample.txt
└── README.md
```

## How to Run

### Prerequisites
- Python 3 installed.
- Visual Studio Code or another Python-compatible editor.

### Execution

1. Clone or download this repository.
2. Open the project folder in VS Code.
3. Open the terminal.
4. Execute:

```bash
python hash.py
```

5. Select an option from the menu.
6. Enter the complete path of the file you want to monitor.

## Testing

The project can be tested using the following scenarios:

| Test | Expected Result |
|---|---|
| Register a new file | Baseline hash generated and stored |
| Register an existing file | Duplicate registration warning |
| Check an unchanged file | Integrity verified |
| Modify a registered file | Modification detected |
| Check an unregistered file | Error message |
| Enter an invalid path | Error message |
| Delete a registered file | Missing-file warning |
| Restart the program | Previous baseline retained |

## Limitations
The baseline hashes are stored in a local JSON file. If an attacker can modify both the monitored file and the database, the integrity check may be bypassed.

Therefore, this project demonstrates fundamental file integrity monitoring rather than a fully tamper-resistant security solution.

## Future Improvements
- Secure baseline storage.
- Automated directory monitoring.
- Timestamped integrity logs.
- Graphical user interface.
- Email or notification alerts.
- Digital signatures for baseline verification.

## Conclusion
This project demonstrates how cryptographic hashing can be applied to file integrity monitoring. By comparing SHA-256 hashes against previously stored baselines, the system can identify unexpected changes and provide a basic mechanism for monitoring file integrity.