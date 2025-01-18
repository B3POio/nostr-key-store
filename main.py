import json
import os
from PyQt5.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
)
from PyQt5.QtGui import QClipboard
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64

# File to store encrypted data
DATA_FILE = "secure_data.json"

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key using PBKDF2 and the provided password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def decrypt_data(encrypted_data: bytes, key: bytes, nonce: bytes) -> str:
    """Decrypt data using AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_data, None).decode()


class InputDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Input Dialog")

        # Set a default size for the dialog
        self.resize(500, 200)

        self.layout = QVBoxLayout()

        # Private Key Input
        self.private_key_label = QLabel("Enter your private key:")
        self.layout.addWidget(self.private_key_label)
        self.private_key_input = QLineEdit()
        self.layout.addWidget(self.private_key_input)

        # Public Key Input
        self.public_key_label = QLabel("Enter your public key:")
        self.layout.addWidget(self.public_key_label)
        self.public_key_input = QLineEdit()
        self.layout.addWidget(self.public_key_input)

        # Password Input
        self.password_label = QLabel("Enter your password:")
        self.layout.addWidget(self.password_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)  # Set input to password mode
        self.layout.addWidget(self.password_input)

        # Submit Button
        self.submit_button = QPushButton("Submit")
        self.submit_button.clicked.connect(self.collect_inputs)
        self.layout.addWidget(self.submit_button)

        self.setLayout(self.layout)

    def collect_inputs(self):
        private_key = self.private_key_input.text()
        public_key = self.public_key_input.text()
        password = self.password_input.text()

        if not private_key or not public_key or not password:
            QMessageBox.critical(self, "Error", "All fields are required!")
        else:
            try:
                # Generate salt and encryption key
                salt = os.urandom(16)
                key = generate_key(password, salt)

                # Encrypt the keys
                aesgcm = AESGCM(key)
                nonce = os.urandom(12)
                encrypted_private_key = aesgcm.encrypt(nonce, private_key.encode(), None)
                encrypted_public_key = aesgcm.encrypt(nonce, public_key.encode(), None)

                # Save encrypted data to file
                data = {
                    "encrypted_private_key": base64.b64encode(encrypted_private_key).decode(),
                    "encrypted_public_key": base64.b64encode(encrypted_public_key).decode(),
                    "salt": base64.b64encode(salt).decode(),
                    "nonce": base64.b64encode(nonce).decode(),
                }

                with open(DATA_FILE, "w") as file:
                    json.dump(data, file)

                QMessageBox.information(self, "Success", "Keys encrypted and saved successfully!")
                self.accept()

            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred: {e}")


class DecryptDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Decrypt Data")

        # Set a default size for the dialog
        self.resize(500, 200)

        self.layout = QVBoxLayout()

        # Password Input
        self.password_label = QLabel("Enter your password to decrypt:")
        self.layout.addWidget(self.password_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        # Submit Button
        self.submit_button = QPushButton("Decrypt")
        self.submit_button.clicked.connect(self.decrypt_data)
        self.layout.addWidget(self.submit_button)

        # Decrypted Data Labels and Buttons
        self.private_key_label = QLabel("")
        self.public_key_label = QLabel("")
        self.layout.addWidget(self.private_key_label)
        self.layout.addWidget(self.public_key_label)

        # Copy to Clipboard Buttons
        self.copy_private_button = QPushButton("Copy Private Key to Clipboard")
        self.copy_private_button.clicked.connect(self.copy_private_key)
        self.layout.addWidget(self.copy_private_button)

        self.copy_public_button = QPushButton("Copy Public Key to Clipboard")
        self.copy_public_button.clicked.connect(self.copy_public_key)
        self.layout.addWidget(self.copy_public_button)

        self.setLayout(self.layout)

    def decrypt_data(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.critical(self, "Error", "Password is required!")
            return

        try:
            # Load encrypted data from file
            with open(DATA_FILE, "r") as file:
                data = json.load(file)

            # Decode data
            encrypted_private_key = base64.b64decode(data["encrypted_private_key"])
            encrypted_public_key = base64.b64decode(data["encrypted_public_key"])
            salt = base64.b64decode(data["salt"])
            nonce = base64.b64decode(data["nonce"])

            # Generate encryption key from password and salt
            key = generate_key(password, salt)

            # Decrypt keys
            private_key = decrypt_data(encrypted_private_key, key, nonce)
            public_key = decrypt_data(encrypted_public_key, key, nonce)

            # Display keys
            self.private_key_label.setText(f"Private Key: {private_key}")
            self.public_key_label.setText(f"Public Key: {public_key}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def copy_private_key(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.private_key_label.text().replace("Private Key: ", ""))
        QMessageBox.information(self, "Copied", "Private key copied to clipboard!")

    def copy_public_key(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.public_key_label.text().replace("Public Key: ", ""))
        QMessageBox.information(self, "Copied", "Public key copied to clipboard!")


def setup_app():
    app = QApplication([])

    if os.path.exists(DATA_FILE):
        # If data file exists, open the decrypt dialog
        decrypt_dialog = DecryptDialog()
        decrypt_dialog.exec_()
    else:
        # Otherwise, open the input dialog to save new values
        dialog = InputDialog()
        dialog.exec_()


if __name__ == "__main__":
    setup_app()
