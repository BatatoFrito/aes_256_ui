'''

This application is an AES encryption/decryption tool with an UI

'''

import base64
import re
from PySide6.QtCore import QSize, Qt, Slot
from PySide6.QtWidgets import QApplication, QPushButton, QWidget, QMainWindow, QLineEdit, QVBoxLayout, QLabel, QTextEdit, QTabWidget
from PySide6.QtGui import QIcon, QPixmap
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Base64 Validator
        self.base64regex = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')

        # Window settings
        self.setWindowTitle('AES Encryptor/Decryptor')
        
        # Central widget settings
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout settings
        self.central_layout = QVBoxLayout()
        self.central_widget.setLayout(self.central_layout)

        # Encryption page
        self.encryption_page = QWidget()
        self.encryption_layout = QVBoxLayout()
        self.encryption_page.setLayout(self.encryption_layout)

        # Encryption form
        self.enc_message_label = QLabel('Message')
        self.encryption_layout.addWidget(self.enc_message_label)
        self.enc_message_text = QTextEdit()
        self.encryption_layout.addWidget(self.enc_message_text)

        self.enc_key_label = QLabel('Key')
        self.encryption_layout.addWidget(self.enc_key_label)
        self.enc_key_line = QLineEdit()
        self.encryption_layout.addWidget(self.enc_key_line)

        self.enc_iv_label = QLabel('IV')
        self.encryption_layout.addWidget(self.enc_iv_label)
        self.enc_iv_line = QLineEdit()
        self.enc_iv_line.setReadOnly(True)
        self.encryption_layout.addWidget(self.enc_iv_line)

        self.enc_cipher_label = QLabel('Cipher')
        self.encryption_layout.addWidget(self.enc_cipher_label)
        self.enc_cipher_text = QTextEdit()
        self.enc_cipher_text.setReadOnly(True)
        self.encryption_layout.addWidget(self.enc_cipher_text)

        self.encryption_send_button = QPushButton('Encrypt Message')
        self.encryption_send_button.clicked.connect(self.encryption)
        self.encryption_layout.addWidget(self.encryption_send_button)

        self.encryption_error_label = QLabel()
        self.encryption_layout.addWidget(self.encryption_error_label)

        # Decryption page
        self.decryption_page = QWidget()
        self.decryption_layout = QVBoxLayout()
        self.decryption_page.setLayout(self.decryption_layout)

        # Decryption form

        self.dec_cipher_label = QLabel('Cipher')
        self.decryption_layout.addWidget(self.dec_cipher_label)
        self.dec_cipher_text = QTextEdit()
        self.decryption_layout.addWidget(self.dec_cipher_text)

        self.dec_key_label = QLabel('Key')
        self.decryption_layout.addWidget(self.dec_key_label)
        self.dec_key_line = QLineEdit()
        self.decryption_layout.addWidget(self.dec_key_line)

        self.dec_iv_label = QLabel('IV')
        self.decryption_layout.addWidget(self.dec_iv_label)
        self.dec_iv_line = QLineEdit()
        self.decryption_layout.addWidget(self.dec_iv_line)

        self.dec_message_label = QLabel('Message')
        self.decryption_layout.addWidget(self.dec_message_label)
        self.dec_message_text = QTextEdit()
        self.dec_message_text.setReadOnly(True)
        self.decryption_layout.addWidget(self.dec_message_text)

        self.decryption_send_button = QPushButton('Decrypt Cipher')
        self.decryption_send_button.clicked.connect(self.decryption)
        self.decryption_layout.addWidget(self.decryption_send_button)

        self.decryption_error_label = QLabel()
        self.decryption_layout.addWidget(self.decryption_error_label)

        # Tab widgets
        self.tab_bar = QTabWidget()
        self.tab_bar.addTab(self.encryption_page, 'Encryption')
        self.tab_bar.addTab(self.decryption_page, 'Decryption')
        self.central_layout.addWidget(self.tab_bar)

    @Slot()
    def encryption(self):
        self.encryption_error_label.setText('')
        message = self.enc_message_text.toPlainText()
        key = self.enc_key_line.text()

        if len(message) == 0:
            self.encryption_error_label.setText("Your message can't be empty")
            return

        if not len(key) in [16, 24, 32]:
            self.encryption_error_label.setText('Your key has to be one of the following sizes: 16, 24, 32')
            return

        encryption_cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
        encrypted_message = base64.b64encode(encryption_cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))).decode('utf-8')
        iv = base64.b64encode(encryption_cipher.iv).decode('utf-8')

        self.enc_cipher_text.setText(encrypted_message)
        self.enc_iv_line.setText(iv)
    
    @Slot()
    def decryption(self):
        self.decryption_error_label.setText('')

        if not self.base64regex.match(self.dec_cipher_text.toPlainText()):
            self.decryption_error_label.setText("Your cipher is not in Base64")
            return
        
        if not self.base64regex.match(self.dec_iv_line.text()):
            self.decryption_error_label.setText("Your IV is not in Base64")
            return
        
        encrypted_message = base64.b64decode(self.dec_cipher_text.toPlainText())
        iv = base64.b64decode(self.dec_iv_line.text())
        key = self.dec_key_line.text()

        if not len(key) in [16, 24, 32]:
            self.decryption_error_label.setText('Your key has to be one of the following sizes: 16, 24, 32')
            return

        decryption_cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv=iv)

        try:
            original_message = unpad(decryption_cipher.decrypt(encrypted_message), AES.block_size).decode('utf-8')
        except(ValueError):
            self.decryption_error_label.setText('Your info is incorrect')
            return

        self.dec_message_text.setText(original_message)

if __name__ == '__main__':

    app = QApplication()

    window = MainWindow()

    window.show()
    app.exec()
