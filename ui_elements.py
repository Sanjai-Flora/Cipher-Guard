from PyQt5.QtWidgets import (
    QSplashScreen, QMessageBox, QLineEdit, QVBoxLayout, QLabel, 
    QPushButton, QHBoxLayout, QDialog,  QTextEdit
)
from PyQt5 import QtCore
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont, QIcon

import re
import os
import argon2
import time 


class NoteDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Note")
        self.setGeometry(100, 100, 600, 400)  #Set dialog size
        layout = QVBoxLayout()
        self.note_input = QTextEdit()
        layout.addWidget(self.note_input)
        buttons = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.accept)
        save_button.setStyleSheet("background-color: yellow;")
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        cancel_button.setStyleSheet("background-color: red;")
        buttons.addWidget(save_button)
        buttons.addWidget(cancel_button)
        layout.addLayout(buttons)
        self.setLayout(layout)

    def get_note(self):
        return self.note_input.toPlainText()
    
class SplashScreen(QSplashScreen):
    def __init__(self):
        super().__init__()
        pixmap = QPixmap(600, 400)
        pixmap.fill(QColor("#62ACC6"))
        painter = QPainter(pixmap)
        
        # Load and draw the logo
        logo = QPixmap("splash_screen.png")
        logo = logo.scaledToWidth(266)  
        logo_x = (pixmap.width() - logo.width()) // 2
        logo_y = 90  # Adjust this value to position the logo
        painter.drawPixmap(logo_x, logo_y, logo)
        painter.setPen(Qt.black)
        font = QFont("Arial", 16, QFont.Bold)
        painter.setFont(font)
         # Draw main text
        text_rect = QRect(0, logo_y + logo.height() + 5, pixmap.width(), 100)
        painter.drawText(text_rect, Qt.AlignCenter, "\nWelcome To Cipher Guard\n\n''Guard Your Digital World: Encrypt with Confidence!''")
        painter.end()
        self.setPixmap(pixmap)
        self.setGeometry(100, 100, 600, 400)  # Set position and size

class InstructionsScreen(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CIPHER GUARD")
        self.setGeometry(100, 100, 600, 400)
        self.setStyleSheet("color: black; background-color: #62ACC6; font : bold;")
        layout = QVBoxLayout(self)

        instructions = """Instructions:
                        1. Entering a Passphrase:
                        * Type a strong passphrase in the "Enter Passphrase" field.
                        * The passphrase strength indicator will help you create a robust passphrase.
                        * Use the eye icon to toggle passphrase visibility

                        2.Choosing an Encryption Algorithm:
                        * Select either "AES-256-GCM" or "ChaCha20-Poly1305".
                        * AES-256-GCM is suitable for normal data.
                        * ChaCha20-Poly1305 is recommended for sensitive data.

                        3.Selecting Files or Folders:
                        * Use "Select File(s)" to choose one or multiple files for encryption/decryption.
                        * Use "Select Folder" to choose an entire folder
                        * Selected items will be displayed in the file label area.

                        4.Encrypting Files/Folders:
                        * After selecting files/folder, algorithm, and entering a passphrase, click "Encrypt".
                        * Confirm your passphrase.
                        * The progress bar will show the encryption progress.
                        * Once complete, your original files will be replaced with encrypted versions.

                        5.Decrypting Files/Folders:
                        * Select the encrypted files/folder.
                        * Choose the same algorithm used for encryption.
                        * Enter the original passphrase.
                        * Click "Decrypt" and confirm the passphrase.
                        * The progress bar will show decryption progress.

                        6.Using Notes:
                        * Click the "Note" button to access the notes feature.
                        * First-time users will need to set a note password.
                        * Any written material can be protected by NOTES.
                        * You can view existing notes and add new ones.
                        * Notes are encrypted for security.

                        7.Viewing History:
                        * Click "View History" to see your encryption/decryption activities.
                        * Enter your password for accessing history.

                        8.Clearing History:
                        * Use "Clear History" to remove selected history entries.
                        * You'll need to enter your password.

                        9.Resetting Passwords:
                        * If you forget your password or note password, use the reset option.
                        * Be aware that resetting will clear all existing history or notes.

                        10.Cancelling Operations:
                        * Use the "Clear" button to reset all inputs and selections.

                        11.Quitting the Application:
                        * Click the "Quit" button to close CIPHERGAURD."""

        text_edit = QTextEdit()
        text_edit.setPlainText(instructions)
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("background-color: white; font : bold;")
        layout.addWidget(text_edit)

        continue_button = QPushButton("Continue")
        continue_button.setStyleSheet("""
            font : bold;                          
            background-color: lightblue;
            border: 2px solid darkblue;
            padding: 5px;
        """)
        continue_button.clicked.connect(self.accept)
        layout.addWidget(continue_button, alignment=Qt.AlignCenter)
        
        dont_show_button = QPushButton("Don't show this again")
        dont_show_button.setStyleSheet("""
            font : bold;                           
            background-color: #EEEBEB;
            border: 2px solid black;
            padding: 5px;
        """)
        dont_show_button.clicked.connect(self.dont_show_again)
        layout.addWidget(dont_show_button, alignment=Qt.AlignCenter)
        
        self.setLayout(layout)
    
    def dont_show_again(self):
        instructions_file = os.path.join(os.path.expanduser("~"), ".encryption_keys", 'show_instructions.txt')
        with open(instructions_file, 'w') as f:
            f.write('False')
        self.accept()


class LoginPage(QDialog):
    def __init__(self, hidden_dir, main_window):  # Add main_window parameter
        super().__init__()
        self.hidden_dir = hidden_dir
        self.main_window = main_window
        self.setWindowTitle("CIPHER GUARD")
        self.setGeometry(100, 100, 600, 400)  # Increased size
        self.setStyleSheet("background-color: #62ACC6; font : bold;")
        
        layout = QVBoxLayout()
        
        # Add logo to the login page
        logo_label = QLabel()
        logo_pixmap = QPixmap("splash_screen.png")
        logo_pixmap = logo_pixmap.scaledToWidth(266)  
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        title_label = QLabel("LOGIN")
        title_label.setStyleSheet("color: black; font-weight: bold; font-size: 24px;")
        layout.addWidget(title_label, alignment=Qt.AlignCenter)
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter Username")
        self.name_input.setStyleSheet("color: black; background-color: white; font : bold;")
        layout.addWidget(self.name_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("color: black; background-color: white; font : bold;")
        
        self.eye_button = QPushButton()
        self.eye_button.setIcon(QIcon('eye_on.png'))
        self.eye_button.setCheckable(True)
        self.eye_button.clicked.connect(self.toggle_password_visibility)
        self.eye_button.setStyleSheet("""
            background-color: white;
            border: none;
        """)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.eye_button)

        layout.addLayout(password_layout)

        self.timer = QtCore.QTimer()
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.auto_hide_password)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        self.login_button.setStyleSheet("""
            font : bold;
            background-color: #9CCDF9;
            border: 2px solid #000000;
            color: black;
            padding: 5px;
        """)
        layout.addWidget(self.login_button)
        
        self.set_password_button = QPushButton("Set Password")
        self.set_password_button.clicked.connect(self.set_password)
        self.set_password_button.setStyleSheet("""
            font : bold;                 
            background-color: #9CCDF9;
            border: 2px solid #000000;
            color: black;
            padding: 5px;
        """)
        layout.addWidget(self.set_password_button)
        
        self.forgot_password_button = QPushButton("Forgot Password")
        self.forgot_password_button.clicked.connect(self.reset_password)
        self.forgot_password_button.setStyleSheet("""
            font : bold; 
            background-color: #9CCDF9;
            border: 2px solid #000000;
            color: black;
            padding: 5px;
        """)
        layout.addWidget(self.forgot_password_button)
        
        self.setLayout(layout)
        
        self.load_password()
        self.password_input.clear()
        
        # Add attempt counter and lock timer
        self.attempt_count = 0
        self.lock_until = 0              
        
    
    def toggle_password_visibility(self):
        # This function changes the visibility of the password in the input field.
        if self.eye_button.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.eye_button.setIcon(QIcon('eye_off.png'))
            self.timer.start(3000)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.eye_button.setIcon(QIcon('eye_on.png'))

    def auto_hide_password(self):
        # This method automatically hides the password after three seconds of being visible.
        self.password_input.setEchoMode(QLineEdit.Password)
        self.eye_button.setChecked(False)
        self.eye_button.setIcon(QIcon('eye_on.png'))
    
    def load_password(self):
        # This function loads the user's password from a file that exists.
        password_file = os.path.join(self.hidden_dir, 'login_password.bin')
        if os.path.exists(password_file):
            self.set_password_button.hide()
            try:
                with open(password_file, 'rb') as f:
                    stored_name, _ = f.read().split(b'\n')  # Only read name
                    self.name_input.setText(stored_name.decode())  # Set the username
            except Exception as e:
                print(f"Error loading username: {e}")
        else:
            self.login_button.hide()
            self.forgot_password_button.hide()
    
    def set_password(self):
        # This function lets the user create a new password for the application.
        name = self.name_input.text()
        password = self.password_input.text()
        if not name or not password:
            QMessageBox.warning(self, 'Error', 'Please enter user name and  password.')
            return
        
        if not self.is_password_strong(password):
            return
        
        ph = argon2.PasswordHasher()
        hash = ph.hash(password)
        
        password_file = os.path.join(self.hidden_dir, 'login_password.bin')
        with open(password_file, 'wb') as f:
            f.write(name.encode() + b'\n' + hash.encode())
        
        QMessageBox.information(self, 'Success', 'Password set successfully.')
        self.set_password_button.hide()
        self.login_button.show()
        self.forgot_password_button.show()
        self.password_input.clear()
    
    def login(self):
         # This function checks the user's password when they try to log in
        if not self.check_attempts():  # Check attempts before proceeding
           return 
        name = self.name_input.text()
        password = self.password_input.text()
        if not name or not password:
            QMessageBox.warning(self, 'Error', 'Please enter the password.')
            return
        
        password_file = os.path.join(self.hidden_dir, 'login_password.bin')
        if not os.path.exists(password_file):
            QMessageBox.warning(self, 'Error', 'No password set. Please set a password first.')
            return
        
        with open(password_file, 'rb') as f:
            stored_name, stored_hash = f.read().split(b'\n')
        
        if name.encode() != stored_name:
            QMessageBox.warning(self, 'Error', 'Incorrect name.')
            return
        
        ph = argon2.PasswordHasher()
        
        try:
            ph = argon2.PasswordHasher()
            ph.verify(stored_hash, password)
            self.main_window.login_password_hash = stored_hash
            self.accept()
        except argon2.exceptions.VerifyMismatchError:
            self.increment_attempts()  # Increment attempts on failed login
            QMessageBox.warning(self, 'Error', 'Incorrect password.')
            self.password_input.clear()  # Clear the password input fiel  
    
    def reset_password(self):
        # This function resets the user's password and deletes all history information in the process.
        reply = QMessageBox.question(self, 'Reset Password', 
                                     'Are you sure you want to reset your password? This will delete all history data.',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            password_file = os.path.join(self.hidden_dir, 'login_password.bin')
            if os.path.exists(password_file):
                os.remove(password_file)
            
            history_file = os.path.join(self.hidden_dir, 'history.bin')
            if os.path.exists(history_file):
                os.remove(history_file)
            
            self.set_password_button.show()
            self.login_button.hide()
            self.forgot_password_button.hide()
            QMessageBox.information(self, 'Password Reset', 'Password has been reset. Please set a new password.')
    
    def is_password_strong(self, password):
        # This function verifies whether the user's password fulfills the minimum strength requirements.
        if len(password) < 12 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password) or not re.search(r'[!@#$%^&*()_+\-=\[\]{};\'\|,.<>\/?]+', password):
            QMessageBox.warning(self, 'Weak Password',
                                'Password too weak!\n'
                                'It must meet the following criteria:\n\n'
                                '- At least 12 characters long\n'
                                '- At least one uppercase letter\n'
                                '- At least one lowercase letter\n'
                                '- At least one digit\n'
                                '- At least one special character (_-$@#)')
            return False
        return True
    
    def increment_attempts(self):
        # increment the attempts
        self.attempt_count += 1
        if self.attempt_count >= 3:
            self.lock_until = time.time() + 60  # Lock for 60 seconds
            QMessageBox.warning(self, 'Error', f'Too many attempts. Try again in {round(self.lock_until - time.time())} seconds.')
            self.password_input.clear()
            self.attempt_count = 0
            # Optionally, you could also temporarily disable the login button here
            # self.login_button.setEnabled(False)

    def check_attempts(self):
        if self.lock_until > time.time():
            QMessageBox.warning(self, 'Error', f'Too many attempts. Try again in {round(self.lock_until - time.time())} seconds.')
            return False
        return True    
    