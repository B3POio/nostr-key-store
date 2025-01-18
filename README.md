# nostr-key-store

## Description
This Python application securely stores and encrypts private and public keys, allowing users to retrieve and decrypt them later with a password. The encrypted data is saved in a local JSON file. The application uses PyQt5 for the graphical user interface and the `cryptography` library for encryption.

---

## Features
- Collects and encrypts private and public keys with a user-provided password.
- Saves encrypted data to a JSON file (`secure_data.json`).
- Allows decryption and retrieval of stored keys with the correct password.
- Supports clipboard copy for decrypted keys.

---

## Prerequisites
- Python 3.11 or higher
- Ensure `pip` is installed and up-to-date:
  ```bash
  python3 -m pip install --upgrade pip
  ```

---

## Setup Instructions

### 1. Create a Virtual Environment
It is recommended to use a virtual environment to isolate dependencies:

```bash
python3 -m venv venv
```

### 2. Activate the Virtual Environment
- **On macOS/Linux**:
  ```bash
  source venv/bin/activate
  ```

- **On Windows**:
  ```cmd
  venv\Scripts\activate
  ```

### 3. Install Dependencies
Install the required dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Running the Application
1. Ensure the virtual environment is activated.
2. Run the application:

```bash
python main.py
```

---

## File Structure
- `main.py`: Main application file.
- `secure_data.json`: File where encrypted data is stored (created automatically upon saving keys).
- `requirements.txt`: Lists required Python packages.

---

## Dependencies
- PyQt5
- cryptography

---

## Notes
- Ensure Python 3.11 or higher is installed.
- If `secure_data.json` already exists, the application will start directly with the decryption dialog.
- If no data is stored, the application will prompt to collect and save keys.

---

## Troubleshooting
If you encounter any issues:
- Ensure Python 3.11 is installed and is the default Python interpreter.
- Ensure the virtual environment is activated when running the application.
- Verify that all dependencies are installed correctly using:
  ```bash
  pip list
  ```
- Check for errors in the terminal for debugging hints.

---

## License
This project is open-source and available under the MIT License.


