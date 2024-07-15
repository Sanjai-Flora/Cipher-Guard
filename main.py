# Import the libraries for file operations, encoding, and system interactions.
import os
import ctypes
import time
import struct
import pickle
import base64
import zxcvbn
import re

# Import PyQt5 modules to generate the graphical user interface.
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtWidgets import  QProgressBar, QDialog, QTextEdit
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QFileDialog, QMessageBox, QLineEdit, QVBoxLayout,QLabel, QPushButton, QHBoxLayout, 
    QDialog, QCheckBox, QInputDialog,QSplitter,QWidget
)
# Import cryptographic libraries for encryption and key derivation.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Import functions from other modules
from crypto_utils import * 
from ui_elements import *


# GUI Application
class CIPHERGAURD(QtWidgets.QWidget):
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle('CIPHER GUARD')
        self.setGeometry(100, 100, 600, 400)
        
        self.setStyleSheet("""
            QMessageBox { 
                background-color: #62ACC6; 
            }
            QMessageBox QPushButton:ok { 
                background-color: yellow;
            }
            QMessageBox QPushButton:cancel {
                background-color: red;
            }
             QInputDialog { 
                background-color: #62ACC6; 
            }
        """)
                         
    
        # Get the proper hidden directory based on the OS.
        self.hidden_dir = os.path.join(os.path.expanduser("~"), ".encryption_keys")
        self.fek_file = os.path.join(self.hidden_dir, 'fek_data.bin')
        self.create_hidden_directory()
        if not os.path.exists(self.fek_file):
            with open(self.fek_file, 'wb') as f:
                pass  # Create an empty binary file
        self.attempt_count = 0
        self.lock_until = 0
        self.selected_paths = []
        self.selected_algorithm = None
        self.initUI()

        
    def create_hidden_directory(self):
        # This method generates a secret directory to store encryption keys.
        if not os.path.exists(self.hidden_dir):
            os.makedirs(self.hidden_dir)
            
            # For Windows
            if os.name == 'nt':
                ctypes.windll.kernel32.SetFileAttributesW(self.hidden_dir, 2)  # 2 is FILE_ATTRIBUTE_HIDDEN
            
            # For Unix-like systems (Linux, macOS)
            elif os.name == 'posix':
                # The folder name starting with a dot makes it hidden on Unix-like systems
                pass
            
            else:
                print("Unsupported operating system for hiding folders.")
        
    def initUI(self):
        # This function initializes the user interface of the application
        self.setWindowTitle('CIPHER GAURD')
        self.setGeometry(100, 100, 600, 450)  # Increased height for progress bar
        
        self.login_password_hash = None
        self.load_login_password()                 
        self.passphrase_input.textChanged.connect(self.update_password_strength)
        
    def load_login_password(self):
        # This function loads the user's login password from a file if it exists
        password_file = os.path.join(self.hidden_dir, 'login_password.bin')
        if os.path.exists(password_file):
            with open(password_file, 'rb') as f:
                _, self.login_password_hash = f.read().split(b'\n')
        
    
        # Define the algorithm button style at the start of initUI.
        self.algorithm_button_style = """
            QPushButton {
                background-color: #9FC5E8;
                border:2px solid #0505E1;;
                color: black;
                font : bold;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 12px;
                margin: 1px 3px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
         """
   
 
         # Create the main layout
        layout = QVBoxLayout()
        
            # Set up label style
        label_font = QFont()
        label_font.setBold(True)
        label_font.setPointSize(14)  # Increased font size
        label_style = "QLabel { color: #333333; }"

        # Function to create styled labels
        def create_styled_label(text):
            label = QLabel(text)
            label.setFont(label_font)
            label.setStyleSheet(label_style)
            return label
        
        # Create and set up UI elements (labels, input fields, buttons, etc.)
        # Passphrase input with eye icon
        self.passphrase_label = create_styled_label('Enter Passphrase:')
        passphrase_layout = QHBoxLayout()
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.eye_button = QPushButton()
        self.eye_button.setIcon(QIcon('eye_on.png'))
        self.eye_button.setCheckable(True)
        self.eye_button.clicked.connect(self.toggle_passphrase_visibility)
        passphrase_layout.addWidget(self.passphrase_input)
        passphrase_layout.addWidget(self.eye_button)
        layout.addWidget(self.passphrase_label)
        layout.addLayout(passphrase_layout)

        # Password strength label
        self.password_strength_label = create_styled_label('Passphrase Strength: Null')
        layout.addWidget(self.password_strength_label)

        # Algorithm selection
        algorithm_layout = QHBoxLayout()
        algorithm_label = create_styled_label("Algorithm:")
        algorithm_layout.addWidget(algorithm_label)
        
        # Update button labels and tooltips
        self.aes_button = QPushButton("AES-256-GCM\nNormal Data")
        self.chacha_button = QPushButton("ChaCha20-Poly1305\nSensitive Data")
        self.aes_button.setStyleSheet(self.algorithm_button_style)
        self.chacha_button.setStyleSheet(self.algorithm_button_style)
        self.aes_button.clicked.connect(lambda: self.set_algorithm("AES-256-GCM"))
        self.chacha_button.clicked.connect(lambda: self.set_algorithm("ChaCha20-Poly1305"))
        algorithm_layout.addWidget(self.aes_button)
        algorithm_layout.addWidget(self.chacha_button)
        layout.addLayout(algorithm_layout)
        
        # File selection
        file_selection_layout = QHBoxLayout()
        self.file_button = QPushButton('Select File(s)')
        self.file_button.clicked.connect(self.select_files)
        self.folder_button = QPushButton('Select Folder')
        self.folder_button.clicked.connect(self.select_folder)
        file_selection_layout.addWidget(self.file_button)
        file_selection_layout.addWidget(self.folder_button)
        layout.addLayout(file_selection_layout)

        self.file_label = QLabel('No File(s) or Folder selected')
        layout.addWidget(self.file_label)

        # Encrypt button
        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt_action)
        layout.addWidget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt_action)
        layout.addWidget(self.decrypt_button)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.hide()  # Initially hide the progress bar
        layout.addWidget(self.progress_bar)
        
        # History label
        self.history_label = create_styled_label('History:')
        layout.addWidget(self.history_label)

        # History buttons
        history_buttons_layout = QHBoxLayout()
        self.view_history_button = QPushButton('View History')
        self.view_history_button.clicked.connect(self.view_history)
        self.clear_history_button = QPushButton('Clear History')
        self.clear_history_button.clicked.connect(self.clear_selected_history)
        history_buttons_layout.addWidget(self.view_history_button)
        history_buttons_layout.addWidget(self.clear_history_button)
        layout.addLayout(history_buttons_layout)
        
        
        # Add note label
        self.note_label = QLabel("Please create a password for the Note before proceeding.")
        self.note_label.setStyleSheet("color: #EEEBEB; font-weight: bold;")
        layout.addWidget(self.note_label)

        # Cancel button
        self.cancel_button = QPushButton('Clear')
        self.cancel_button.clicked.connect(self.cancel_action)
        self.cancel_button.setFixedSize(80, 30)  # Make the button small

        # Quit button
        self.quit_button = QPushButton('Quit')
        self.quit_button.clicked.connect(self.close)
        self.quit_button.setFixedSize(80, 30)  # Make the button small

        # Add Cancel and Quit buttons to a horizontal layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.quit_button)
        layout.addLayout(button_layout)
        
          
        # Apply style to existing labels
        for label in [self.passphrase_label, self.password_strength_label, self.file_label]:
            label.setFont(label_font)
            label.setStyleSheet(label_style)
            
        # Add this near the end of initUI
        note_password_file = os.path.join(self.hidden_dir, 'note_password.bin')
        if os.path.exists(note_password_file):
            self.note_label.hide()
        else:
             self.note_label.show()    
        
        # ... (detailed UI setup code)
        self.setLayout(layout)
        
        # Set a background color for the main window
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor("#62ACC6"))  
        self.setPalette(palette)

        # Style for file and folder selection buttons
        file_folder_button_style = """
            QPushButton {
                color: black;
                background-color: #EEEBEB;
                border: 2px solid #000000;
                font : bold;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 13px;
                margin: 1px 3px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #E06666;
            }
        """
        self.file_button.setStyleSheet(file_folder_button_style)
        self.folder_button.setStyleSheet(file_folder_button_style)

        # Style for encrypt and decrypt buttons
        encrypt_decrypt_button_style = """
            QPushButton {
                color: black;
                background-color: #9FC5E8;
                border: 2px solid #0505E1;
                font : bold;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 15px;
                margin: 1px 3px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #3587D2;
            }
        """
        self.encrypt_button.setStyleSheet(encrypt_decrypt_button_style)
        self.decrypt_button.setStyleSheet(encrypt_decrypt_button_style)

        # Style for history-related buttons
        history_button_style = """
            QPushButton {
                color: black;
                background-color: #F2BB82;
                border: 2px solid #FF9900;
                font : bold;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 13px;
                margin: 1px 3px;
                border-radius: 8px;
            }
            QPushButton:hover {
                color: black;
                background-color: #FD8100;
            }
        """
        self.view_history_button.setStyleSheet(history_button_style)
        self.clear_history_button.setStyleSheet(history_button_style)

        # Style for cancel and quit buttons
        small_button_style = """
            QPushButton {
                background-color: red;
                border: none;
                color: white;
                font : bold;
                padding: 5px 10px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #F70000;
            }
        """
        self.cancel_button.setStyleSheet(small_button_style)
        self.quit_button.setStyleSheet(small_button_style)

        # Style for passphrase input
        self.passphrase_input.setStyleSheet("""
            QLineEdit {
                color: black;
                border: 2px solid #000000;
                border-radius: 10px;
                padding: 5px;
                font : bold;
                background-color: #FFFFFF;
                selection-background-color: #000000;
            }
        """)

        # Style for file label
        self.file_label.setStyleSheet("""
            QLabel {
                color: black;
                background-color: #EEEEEE;
                border: 2px solid #000000;
                border-radius: 10px;
                padding: 8px;
            }
        """)

        # Style for progress bar
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
                margin: 1px;
            }
        """)
        
        # Add Note button
        self.note_button = QPushButton('Note')
        self.note_button.setFixedSize(80, 35)
        self.note_button.clicked.connect(self.handle_note)
        self.note_button.setStyleSheet("""
            QPushButton {
                background-color: #EEEBEB;
                border: 2px solid #000000;
                color: black;
                font : bold;
                padding: 5px 10px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #3587D2;
            }
        """)

        # Add Note button to layout
        button_layout.addWidget(self.note_button)
        button_layout.addStretch()

        

        self.aes_button.setStyleSheet(self.algorithm_button_style)
        self.chacha_button.setStyleSheet(self.algorithm_button_style)  
        
        
        # Timer for auto-hiding passphrase
        self.timer = QtCore.QTimer()
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.auto_hide_passphrase)

        # Set up drag and drop functionality
        self.setAcceptDrops(True)
        
    # Provides methods for managing UI interactions and encryption/decryption processes, including set_algorithm, toggle_passphrase_visibility, encrypt_action, and decrypt_action.
    
    
    def set_algorithm(self, algorithm):
         # This function sets the selected encryption algorithm and updates the UI accordingly
        self.selected_algorithm = algorithm
        if algorithm == "AES-256-GCM":
           self.aes_button.setStyleSheet("background-color: #1565C0;")
           self.chacha_button.setStyleSheet(self.algorithm_button_style)
        else:
            self.chacha_button.setStyleSheet("background-color: #1565C0;")
            self.aes_button.setStyleSheet(self.algorithm_button_style)

    def clear_algorithm_selection(self):
        # This function clears the selected encryption algorithm and resets the UI
        self.selected_algorithm = None
        self.chacha_button.setStyleSheet("")
        self.aes_button.setStyleSheet("")
    
            
    def view_history(self):
        # This function shows the user's encryption history after verifying their login password.
        if self.login_password_hash:
            password, ok = QInputDialog.getText(
                self, 'History Access',
                'Enter your login password:',
                QLineEdit.Password
            )
            if ok:
                ph = argon2.PasswordHasher()
                try:
                    ph.verify(self.login_password_hash, password)
                    self.show_history()
                except argon2.exceptions.VerifyMismatchError:
                    QMessageBox.warning(self, 'Error', 'Incorrect password.')
        else:
            QMessageBox.warning(self, 'Error', 'Login password not set.')


    def show_history(self):
        # This function shows the encryption history in a separate dialog.
        history = self.get_history()
        if history:
            dialog = QDialog(self)
            dialog.setWindowTitle("Encryption History")
            dialog.setGeometry(100, 100, 800, 600)
            dialog.setStyleSheet("color: black; background-color: #62ACC6;")
            layout = QVBoxLayout()
            text_edit = QtWidgets.QTextEdit()
            text_edit.setPlainText(history)
            text_edit.setReadOnly(True)
            text_edit.setStyleSheet("background-color: white;")
            layout.addWidget(text_edit)
            dialog.setLayout(layout)
            dialog.exec_()
        else:
            QMessageBox.information(self, 'Info', "No history available.")

    def get_history(self):
         # This function retrieves the encryption history from a file
        history_file = os.path.join(self.hidden_dir, 'history.bin')
        if os.path.exists(history_file):
            try:
                with open(history_file, 'rb') as file:
                    history = pickle.load(file)
                entries = [f"{entry['timestamp']} - {entry['action']} - {entry['file_path']}" for entry in history]
                return '\n'.join(entries)
            except (pickle.UnpicklingError, EOFError):
                return None  # Handle potential errors gracefully
        return None

    def clear_selected_history(self):
        # This function allows the user to clear selected history items after verifying their login password.
        if self.login_password_hash:
            password, ok = QInputDialog.getText(
                self, 'History Access',
                'Enter your login password:',
                QLineEdit.Password
            )
            if ok:
                ph = argon2.PasswordHasher()
                try:
                    ph.verify(self.login_password_hash, password)
                    self.proceed_to_clear_history()
                except argon2.exceptions.VerifyMismatchError:
                    QMessageBox.warning(self, 'Error', 'Incorrect password.')
        else:
            QMessageBox.warning(self, 'Error', 'Login password not set.')
       
            
    def hash_password(self, password):
        # This function hashes the user's password with Argon2id for security.
        salt = os.urandom(16)
        hashed_password = argon2.PasswordHasher(
            time_cost=2, memory_cost=64 * 1024, parallelism=8, salt_len=16, hash_len=32
        ).hash(password.encode() + salt) # Add salt to the password before hashing
        return base64.b64encode(salt + hashed_password.encode()).decode()
    
    def verify_password(self, password, stored_hash):
        # This function compares the user's password with a saved hash.
        try:
            decoded_hash = base64.b64decode(stored_hash.encode())
            salt = decoded_hash[:16] 
            stored_password_hash = decoded_hash[16:].decode()
            argon2.PasswordHasher().verify(stored_password_hash, password.encode() + salt)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False

    def proceed_to_clear_history(self):
        # This function deletes the user's encryption history after they confirm their selection.
        history_file = os.path.join(self.hidden_dir, 'history.bin')
        if os.path.exists(history_file):
            try:
                with open(history_file, 'rb') as file:
                    history = pickle.load(file)
            except (pickle.UnpicklingError, EOFError):
                QMessageBox.warning(self, 'Error', 'Error loading history.')
                return

            if not history:
                QMessageBox.information(self, 'Info', "No history available to clear.")
                return

            dialog = QDialog(self)
            dialog.setWindowTitle("Clear History")
            dialog.setStyleSheet("color: black; background-color: #62ACC6;")
            layout = QVBoxLayout()
            checkboxes = []

            for entry in history:
                checkbox = QCheckBox(
                    f"{entry['timestamp']} - {entry['action']} - {entry['file_path']}"
                )
                checkboxes.append(checkbox)
                layout.addWidget(checkbox)

            clear_button = QPushButton("Clear Selected")
            clear_button.clicked.connect(dialog.accept)
            clear_button.setStyleSheet("""
                background-color: #E7E2E2;
                font : bold;
                border: 2px solid black;
                color: black;
                padding: 5px;
            """)
            layout.addWidget(clear_button)

            dialog.setLayout(layout)

            if dialog.exec_():
                new_history = [
                    entry
                    for entry, checkbox in zip(history, checkboxes)
                    if not checkbox.isChecked()
                ]
                with open(history_file, 'wb') as file:
                    pickle.dump(new_history, file)
                QMessageBox.information(
                    self, 'Success', "Selected history entries have been cleared."
                )
        else:
            QMessageBox.information(self, 'Info', "No history available to clear.")
            
            
    def handle_note(self):
        # This function handles the "Note" button click, requiring the user to enter or confirm their note password.
        note_password_file = os.path.join(self.hidden_dir, 'note_password.bin')
        if os.path.exists(note_password_file):
            with open(note_password_file, 'r') as file:
                self.note_password_hash = file.read()
            self.note_label.hide()  # Hide the label if password exists
            self.access_notes()
        else:
            self.note_label.show()  # Show the label if password doesn't exist
            self.set_note_password()

    def set_note_password(self):
        # This function lets the user to  create a password for accessing notes.
        password, ok = QInputDialog.getText(
            self, 'Set Note Password',
            'Enter a password for note access:',
            QLineEdit.Password
        )
        if ok and password:
            confirm_password, ok = QInputDialog.getText(
                self, 'Confirm Password',
                'Confirm the password:',
                QLineEdit.Password
            ) 
            if ok and password == confirm_password:
                self.note_password_hash = self.hash_password(password)
                note_password_file = os.path.join(self.hidden_dir, 'note_password.bin')   
                with open(note_password_file, 'w') as file:
                    file.write(self.note_password_hash)
                QMessageBox.information(self, 'Success', 'Note password set successfully.')
                self.note_label.hide()  # Hide the label after setting the password

            else:
                 QMessageBox.warning(self, 'Error', 'Passwords do not match.')            
        
                 
    def access_notes(self):
        # This function invites the user to enter their note password and grants access to notes if the password is correct.
        password, ok = QInputDialog.getText(
            self, 'Note Access',
            'Enter the note password:',
            QLineEdit.Password
        )
        if ok:
            if self.verify_password(password, self.note_password_hash):
                self.view_notes(password)
            else:
                reply = QMessageBox.question(self, 'Forgotten Password', 
                                             'Incorrect password. Have you forgotten your note password?\n Are you sure you want to reset your password?\nThis will delete all Note  data.',
                                             QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.reset_note_password()
                else:
                    QMessageBox.warning(self, 'Error', 'Access denied.')

    def reset_note_password(self):
        # This function allows the user to reset their note password, If reset indicates that existing notes will be cleared. 
        new_password, ok = QInputDialog.getText(
            self, 'Reset Note Password', 
            'Enter a new password for note access:',
            QLineEdit.Password
        )
        if ok and new_password:
            confirm_password, ok = QInputDialog.getText(
                self, 'Confirm New Password', 
                'Confirm the new password:',
                QLineEdit.Password
            )
            if ok and new_password == confirm_password:
                self.note_password_hash = self.hash_password(new_password)
                note_password_file = os.path.join(self.hidden_dir, 'note_password.bin')
                with open(note_password_file, 'w') as file:
                    file.write(self.note_password_hash)
            
                # Clear existing notes
                note_file = os.path.join(self.hidden_dir, 'notes.bin')
                if os.path.exists(note_file):
                    os.remove(note_file)
            
                QMessageBox.information(self, 'Success', 'Note password reset successfully. Existing notes have been cleared.')
            else:
                QMessageBox.warning(self, 'Error', 'Passwords do not match.')            
        


    def view_notes(self, password):
        # This function displays the user's notes in a separate dialog, allowing them to view and add new notes
        notes = self.load_notes(password)
        dialog = QDialog(self)
        dialog.setWindowTitle("Notes")
        dialog.setGeometry(100, 100, 800, 600)
        dialog.setStyleSheet("color: black; background-color: #62ACC6;")
        layout = QVBoxLayout()

        splitter = QSplitter(QtCore.Qt.Vertical)

        # Existing Notes Section
        existing_notes_widget = QWidget()
        existing_notes_layout = QVBoxLayout(existing_notes_widget)
        
        existing_notes_label = QLabel("Existing Notes:")
        existing_notes_layout.addWidget(existing_notes_label)
        
        self.notes_view = QTextEdit()
        self.notes_view.setPlainText("\n\n".join(notes))
        self.notes_view.setReadOnly(True)
        self.notes_view.setStyleSheet("background-color: white;")
        existing_notes_layout.addWidget(self.notes_view)
        
        splitter.addWidget(existing_notes_widget)

        # New Note Section
        new_note_widget = QWidget()
        new_note_layout = QVBoxLayout(new_note_widget)
        
        new_note_label = QLabel("Add New Note:")
        new_note_layout.addWidget(new_note_label)
        
        self.new_note_input = QTextEdit()
        self.new_note_input.setStyleSheet("background-color: white;")
        new_note_layout.addWidget(self.new_note_input)
        
        splitter.addWidget(new_note_widget)

        layout.addWidget(splitter)

        button_layout = QHBoxLayout()
        add_button = QPushButton("Add Note")
        add_button.clicked.connect(lambda: self.add_note(password))
        add_button.setStyleSheet("""
            background-color: #E7E2E2;
            border: 2px solid black;
            font : bold;
            color: black;
            padding: 5px;
        """)
        button_layout.addWidget(add_button)

        clear_button = QPushButton("Clear Selected Notes")
        clear_button.clicked.connect(lambda: self.clear_selected_notes(password))
        clear_button.setStyleSheet("""
            background-color: #E7E2E2;
            border: 2px solid black;
            font : bold;
            color: black;
            padding: 5px;
        """)
        button_layout.addWidget(clear_button)

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        close_button.setStyleSheet("""
            background-color: red;
            font : bold;
            color: white;
            padding: 5px;
        """)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

        dialog.setLayout(layout)
        dialog.exec_()
        
    def clear_selected_notes(self, password):
         # This function allows the user to clear selected notes from their notes list
        notes = self.load_notes(password)
        if not notes:
            QMessageBox.information(self, 'Info', "No notes available to clear.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Clear Notes")
        dialog.setStyleSheet("color: black; background-color: #62ACC6;")
        layout = QVBoxLayout()
        checkboxes = []

        for i, note in enumerate(notes):
            checkbox = QCheckBox(f"Note {i+1}: {note[:30]}...")
            checkboxes.append(checkbox)
            layout.addWidget(checkbox)

        clear_button = QPushButton("Clear Selected")
        clear_button.clicked.connect(dialog.accept)
        layout.addWidget(clear_button)

        dialog.setLayout(layout)

        if dialog.exec_():
            new_notes = [note for note, checkbox in zip(notes, checkboxes) if not checkbox.isChecked()]
            self.save_notes(new_notes, password)
            self.notes_view.setPlainText("\n\n".join(new_notes))
            QMessageBox.information(self, 'Success', "Selected notes have been cleared.")

    def add_note(self, password):
        # This function adds a new note to the user's notes list
        new_note = self.new_note_input.toPlainText()
        if new_note:
            notes = self.load_notes(password)
            notes.append(new_note)
            self.save_notes(notes, password)
            self.notes_view.setPlainText("\n\n".join(notes))
            self.new_note_input.clear()
            QMessageBox.information(self, 'Success', 'Note added successfully.')
        else:
            QMessageBox.warning(self, 'Error', 'Note cannot be empty.')
    
    def load_notes(self, password):
        # This function loads the user's notes from a file, decrypting them using the provided password
        note_file = os.path.join(self.hidden_dir, 'notes.bin')
        if os.path.exists(note_file):
            with open(note_file, 'rb') as file:
                encrypted_notes = file.read()
            try:
                decrypted_notes = self.decrypt_data(encrypted_notes, password)
                return pickle.loads(decrypted_notes)
            except:
                return []
        return []

    def save_notes(self, notes, password):
        # This function saves the user's notes to a file, encrypting them using the provided password
        note_file = os.path.join(self.hidden_dir, 'notes.bin')
        encrypted_notes = self.encrypt_data(pickle.dumps(notes), password)
        with open(note_file, 'wb') as file:
            file.write(encrypted_notes)

    def encrypt_data(self, data, password):
        # This function encrypts data using a key derived from the provided password
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        encrypted_data = cipher.encrypt(nonce, data, None)
        return salt + nonce + encrypted_data

    def decrypt_data(self, encrypted_data, password):
        # This function decrypts data using a key derived from the provided password
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        key = self.derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)

    def derive_key(self, password, salt):
        # This function derives a key from a password and a salt using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key  # This will be a 32-byte key
    
    def toggle_passphrase_visibility(self):
        # This function sets the visibility of the passphrase in the input field.
        if self.eye_button.isChecked():
            self.passphrase_input.setEchoMode(QLineEdit.Normal)
            self.eye_button.setIcon(QIcon('eye_off.png'))
            self.timer.start(3000)  # Start timer for 3 seconds
        else:
            self.passphrase_input.setEchoMode(QLineEdit.Password)
            self.eye_button.setIcon(QIcon('eye_on.png')) 

    def auto_hide_passphrase(self):
        # This function automatically hides the passphrase after 3 seconds of being visible
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.eye_button.setChecked(False)
        self.eye_button.setIcon(QIcon('eye_on.png'))  

    def select_files(self):
        # This function allows the user to select one or more files for encryption or decryption
        options = QFileDialog.Options()
        files, _ = QFileDialog.getOpenFileNames(self, "Select File(s)", "", "All Files (*)", options=options)
        if files:
            self.selected_paths = files
            self.update_file_label()

    def select_folder(self):
        # This function allows the user to select a folder for encryption or decryption
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.selected_paths = [folder]
            self.update_file_label()

    def update_file_label(self):
        # This function updates the UI to display the selected files or folder
        if self.selected_paths:
            self.file_label.setText("\n".join(self.selected_paths))
        else:
            self.file_label.setText('No File(s) or Folder selected')

    def encrypt_action(self):
        # This function handles the encryption process, encrypting selected files or folders using the provided passphrase and algorithm
        if not self.check_attempts():
            return
    
        passphrase = self.passphrase_input.text()
        if not passphrase:
            QMessageBox.warning(self, 'No Passphrase', 'Please enter a passphrase.')
            return

        if not self.is_passphrase_strong(passphrase):
            return

        if self.selected_algorithm is None:
            QMessageBox.warning(self, 'Error', 'Please select an encryption Algorithm.')
            return
            
        if not self.selected_paths:
            QMessageBox.warning(self, 'Error', 'Please select File(s) or a Folder.')
            return
        
        # Check if any files or folders are already encrypted
        if any(path.endswith('.encrypted') for path in self.selected_paths):
            QMessageBox.warning(self, 'Error', 'Some File(s) or Folder are already encrypted.Please select unencrypted file(s) or folder.')
            return

        # Reconfirm passphrase
        confirm_passphrase, confirm = QtWidgets.QInputDialog.getText(self, 'Confirm Passphrase and Keep in mind', 
                                                                'NOTE :\n1 : Please remember the passphrase that you entered, Your File(s) or Folder will be permanently unrecoverable without it.\n2 : Please avoid encrypting files or folders with the same passphrase.\n3 : Apply the same Decryption algorithm that you used for the Encryption. \n4 : Remember that resetting your login password will also erase any information stored in your history if you forget it.\n5 : If you encrypt multiple files, you must utilize the same multiple files to decrypt the content; otherwise, it cannot be decrypted again.\n6 : Remember that resetting your Note password will also erase any information stored in your Note if you forget it.\nRe-enter the passphrase for the selected files or folders to be encrypted. ', 
                                                                QtWidgets.QLineEdit.Password)
        if not confirm or confirm_passphrase != passphrase:
            QMessageBox.warning(self, 'Error', 'Passphrases do not match.')
            return

        try:
            salt = os.urandom(16)
            
            # Choose key derivation function based on selected algorithm
            if self.selected_algorithm == "ChaCha20-Poly1305":
                derived_key = derive_key_argon2id(passphrase, salt)
            else:  # AES-256-GCM
                derived_key = derive_key_scrypt(passphrase, salt)
 
            fek = os.urandom(32)
            encrypted_fek = encrypt_fek(fek, derived_key, self.selected_algorithm)

            # Load existing FEK data
            fek_data = self.load_fek_data()

            # Add new FEK data
            fek_id = max(fek_data.keys()) + 1 if fek_data else 1
            fek_data[fek_id] = {
                'encrypted_fek': encrypted_fek,
                'salt': salt,
                'algorithm': self.selected_algorithm,
                'files': []
            }

            self.progress_bar.show()  # Show progress bar
            self.progress_bar.setValue(0)
            total_bytes = 0
            for path in self.selected_paths:
                if os.path.isfile(path):
                    total_bytes += os.path.getsize(path)
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            total_bytes += os.path.getsize(os.path.join(root, file))
            
            bytes_processed = 0
            
            def progress_callback(bytes_read, file_size):
                nonlocal bytes_processed
                bytes_processed += bytes_read
                progress = int((bytes_processed / total_bytes) * 100)
                self.progress_bar.setValue(progress)
                QtWidgets.QApplication.processEvents()  # Update GUI

            for path in self.selected_paths:
                if os.path.isfile(path):
                    encrypt_file(path, fek, self.selected_algorithm, progress_callback)
                    fek_data[fek_id]['files'].append(path + '.encrypted')
                elif os.path.isdir(path):
                    encrypt_folder(path, fek, self.selected_algorithm, progress_callback)
                    fek_data[fek_id]['files'].append(path + '.encrypted')
                    
            # Save updated FEK data
            self.save_fek_data(fek_data)

            update_history("Encrypted", self.selected_paths, self.hidden_dir)
            QMessageBox.information(self, 'Success', "Selected File(s)/Folder have been encrypted.")
            self.file_label.setText('No file(s) or folder selected')
            self.passphrase_input.clear()
            self.selected_paths = []
            self.attempt_count = 0  # Reset attempt count after successful encryption
            self.clear_algorithm_selection()  # Clear algorithm selection after encryption
            self.progress_bar.hide()  # Hide the progress bar after encryption
            
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def decrypt_action(self):
        # This function handles the decryption process, decrypting selected files or folders using the provided passphrase and algorithm
        if not self.check_attempts():
           return

        passphrase = self.passphrase_input.text()
        if not passphrase:
           QMessageBox.warning(self, 'No Passphrase', 'Please enter a passphrase.')
           return

        if not self.is_passphrase_strong(passphrase):
            return

        if self.selected_algorithm is None:
            QMessageBox.warning(self, 'Error', 'Please select a decryption Algorithm.')
            return

        if not self.selected_paths:
           QMessageBox.warning(self, 'Error', 'Please select File(s) or a Folder.')
           return

        # Reconfirm passphrase
        confirm_passphrase, confirm = QtWidgets.QInputDialog.getText(self, 'Confirm Passphrase and Keep in mind', 
                                                        'NOTE :\n1 : Please remember the passphrase that you entered, Your File(s) or Folder will be permanently unrecoverable without it.\n2 : Please avoid encrypting files or folders with the same passphrase.\n3 : Apply the same Decryption algorithm that you used for the Encryption. \n4 : Remember that resetting your login password will also erase any information stored in your history if you forget it.\n5 : If you encrypt multiple files, you must utilize the same multiple files to decrypt the content; otherwise, it cannot be decrypted again.\n6 : Remember that resetting your Note password will also erase any information stored in your Note if you forget it.\nRe-enter the passphrase for the selected files or folders to be decrypted. ', 
                                                        QtWidgets.QLineEdit.Password)
        if not confirm or confirm_passphrase != passphrase:
           QMessageBox.warning(self, 'Error', 'Passphrases do not match.')
           return
    

        try:
            # Load FEK data
            fek_data = self.load_fek_data()
        
            for path in self.selected_paths:
                fek_id = None
                for id, data in fek_data.items():
                    if path in data['files']:
                       fek_id = id
                       break

                if fek_id is None:
                    raise ValueError(f"Key missing. Use encrypted File(s) or Folder(s) to decrypt.")
        
                salt = fek_data[fek_id]['salt']
                stored_algorithm = fek_data[fek_id]['algorithm']
        
                # Check if the selected algorithm matches the stored algorithm
                if stored_algorithm != self.selected_algorithm:
                    raise ValueError(f"Incorrect Algorithm selected. This file was encrypted with {stored_algorithm}.")
         
                # Choose key derivation function based on stored algorithm
                if stored_algorithm == "ChaCha20-Poly1305":
                    derived_key = derive_key_argon2id(passphrase, salt)
                else:  # AES-256-GCM
                    derived_key = derive_key_scrypt(passphrase, salt)

                encrypted_fek = fek_data[fek_id]['encrypted_fek']
        
                try:
                    fek = decrypt_fek(encrypted_fek, derived_key, stored_algorithm)
                except ValueError:
                    raise ValueError("Incorrect passphrase. Please try again.")

                # Verify the decrypted FEK before proceeding with file decryption
                if len(fek) != 32:  # AES-256 key should be 32 bytes
                    raise ValueError("Decryption failed. Incorrect passphrase or corrupted data.")

                self.progress_bar.show()
                self.progress_bar.setValue(0)
                total_bytes = 0
                if os.path.isfile(path):
                   total_bytes += os.path.getsize(path)
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            if file.endswith('.encrypted'):
                                total_bytes += os.path.getsize(os.path.join(root, file))

                bytes_processed = 0
                def progress_callback(bytes_read, file_size):
                   nonlocal bytes_processed
                   bytes_processed += bytes_read
                   progress = int((bytes_processed / total_bytes) * 100)
                   self.progress_bar.setValue(progress)
                   QtWidgets.QApplication.processEvents() 
                   
                if os.path.isfile(path):
                   decrypt_file(path, fek, stored_algorithm, progress_callback)
                elif os.path.isdir(path):
                     decrypt_folder(path, fek, stored_algorithm, progress_callback)

                # Remove the decrypted file from FEK data
                fek_data[fek_id]['files'].remove(path)
                if not fek_data[fek_id]['files']:
                   del fek_data[fek_id]

            # Save updated FEK data
            self.save_fek_data(fek_data)
        
            update_history("Decrypted", self.selected_paths, self.hidden_dir)
            QMessageBox.information(self, 'Success', "Selected File(s)/Folder have been decrypted.")
            self.file_label.setText('No file(s) or folder(s) selected')
            self.passphrase_input.clear()
            self.selected_paths = []
            self.attempt_count = 0
            self.clear_algorithm_selection()  # Clear algorithm selection after decryption
            self.progress_bar.hide()  # Hide the progress bar after decryption
        except ValueError as e:
            self.increment_attempts()
            QMessageBox.critical(self, 'Error', str(e))
        except Exception as e:
             self.increment_attempts()
             QMessageBox.critical(self, 'Error', f"Incorrect passphrase. Please try again: {str(e)}") 
             
    def update_password_strength(self):
        """Calculates and updates the password strength label."""
        passphrase = self.passphrase_input.text()

        # Handle empty passphrase to avoid the IndexError
        if not passphrase:  
            self.password_strength_label.setText('Passphrase Strength: ')
            return 

        try:
            strength_info = zxcvbn.zxcvbn(passphrase)
            score = strength_info['score']


            if score == 0:
                strength = 'Very Weak'
                color = '#FF0000'  # Red
            elif score == 1:
                strength = 'Weak'
                color = '#FF6600'  # Darker Orange
            elif score == 2:
                strength = 'Medium'
                color = '#CCFF00'  #light green
            elif score == 3:
                strength = 'Strong'
                color = '#00FF33'  # Green
            else:
                strength = 'Very Strong'
                color = '#000099'  # dark blue

            # Add white background to the strength text
            self.password_strength_label.setText(
                f'Passphrase Strength: <span style="background-color: white; padding: 2px; border-radius: 3px;"><font color="{color}">{strength}</font></span>'
            )

        except Exception as e: 
            # # Consider reporting the error for debugging. 
            print(f"Error calculating password strength: {e}")
            self.password_strength_label.setText('Passphrase Strength: Error')    

    def is_passphrase_strong(self, passphrase):
        results = zxcvbn.zxcvbn(passphrase)
        if len(passphrase) < 12 or not any(c.isupper() for c in passphrase) or not any(c.islower() for c in passphrase) or not any(c.isdigit() for c in passphrase) or not re.search(r'[!@#$%^&*()_+\-=\[\]{};\'\|,.<>\/?]+', passphrase):
            QMessageBox.warning(self, 'Weak Passphrase',
                                'Passphrase too weak!\n'
                                'It must meet the following criteria:\n\n'
                                '- At least 12 characters long\n'
                                '- At least one uppercase letter\n'
                                '- At least one lowercase letter\n'
                                '- At least one digit\n'
                                '- At least one special character (_-$@#)')
            return False

        # If the passphrase meets the criteria, use zxcvbn for additional analysis
        if results['score'] >= 3:
            return True
        else:
            # Check for empty suggestions list
            if results['feedback']['suggestions']:
                feedback = results['feedback']['suggestions'][0] 
                QMessageBox.warning(self, 'Weak Passphrase', f"{feedback}")
            else:
                QMessageBox.warning(self, 'Weak Passphrase', f"Please make your passphrase stronger")
            return False
        
    def check_attempts(self):
        if self.lock_until > time.time():
            QMessageBox.warning(self, 'Error', f'Too many attempts. Try again in {round(self.lock_until - time.time())} seconds.')
            return False
        return True

    def increment_attempts(self):
        # increment the attempts
        self.attempt_count += 1
        if self.attempt_count >= 3:
            self.lock_until = time.time() + 60  # Lock for 60 seconds

    def cancel_action(self):
        # Clear all user input
        self.passphrase_input.clear()
        self.file_label.setText('No files or folders selected')
        self.selected_paths = []
        self.password_strength_label.setText('Passphrase Strength: Weak')
        self.clear_algorithm_selection()  # Clear algorithm selection

        QMessageBox.information(self, 'Cancelled', 'All input has been cleared.')

    def clear_algorithm_selection(self):
        # clear the selected algorithm
        self.selected_algorithm = None
        self.aes_button.setStyleSheet(self.algorithm_button_style)
        self.chacha_button.setStyleSheet(self.algorithm_button_style)

    def load_fek_data(self):
        # Load File Encryption Key data from the file
        fek_data = {}
        if os.path.exists(self.fek_file):
            with open(self.fek_file, 'rb') as f:
                while True:
                    try:
                        # Read FEK data structure
                        fek_id = struct.unpack('I', f.read(4))[0]
                        encrypted_fek_len = struct.unpack('I', f.read(4))[0]
                        encrypted_fek = f.read(encrypted_fek_len)
                        salt = f.read(16)
                        algorithm_len = struct.unpack('I', f.read(4))[0]
                        algorithm = f.read(algorithm_len).decode()
                        num_files = struct.unpack('I', f.read(4))[0]
                        files = [f.read(struct.unpack('I', f.read(4))[0]).decode() for _ in range(num_files)]
                        fek_data[fek_id] = {
                            'encrypted_fek': encrypted_fek,
                            'salt': salt,
                            'algorithm': algorithm,
                            'files': files
                        }
                    except struct.error:
                        break  # End of file
        return fek_data

    def save_fek_data(self, fek_data):
        # Save File Encryption Key data to the file
        with open(self.fek_file, 'wb') as f:
            for fek_id, data in fek_data.items():
                # Write FEK data structure
                f.write(struct.pack('I', fek_id))
                f.write(struct.pack('I', len(data['encrypted_fek'])))
                f.write(data['encrypted_fek'])
                f.write(data['salt'])
                f.write(struct.pack('I', len(data['algorithm'])))
                f.write(data['algorithm'].encode())
                f.write(struct.pack('I', len(data['files'])))
                for file in data['files']:
                    f.write(struct.pack('I', len(file)))
                    f.write(file.encode())

if __name__ == "__main__":
    # Create Qt Application
    app = QtWidgets.QApplication([])
    
    # Show splash screen
    splash = SplashScreen()
    splash.show()
    
    # Create main window
    window = CIPHERGAURD()
    
    # Create login page
    login_page = LoginPage(window.hidden_dir, window)
    
    # Function to show login page
    def show_login():
        splash.close()
        if login_page.exec_() == QDialog.Accepted:
            show_instructions_or_main()
        else:
            app.quit()
    
    # Function to show instructions or main window
    def show_instructions_or_main():
        instructions_file = os.path.join(window.hidden_dir, 'show_instructions.txt')
        if os.path.exists(instructions_file):
            with open(instructions_file, 'r') as f:
                show_instructions = f.read().strip() == 'True'
        else:
            show_instructions = True
        
        if show_instructions:
            instructions = InstructionsScreen()
            if instructions.exec_() == QDialog.Accepted:
                window.show()
            else:
                app.quit()
        else:
            window.show()
    
    # Close splash screen and show login page after 3 seconds
    QTimer.singleShot(3000, show_login)
    
    app.exec_()