'''

This application is an AES encryption/decryption tool with an UI

'''

import base64
from PySide6.QtCore import QSize, Qt, Slot
from PySide6.QtWidgets import QApplication, QPushButton, QWidget, QGridLayout, QMainWindow, QLineEdit, QVBoxLayout, QLabel, QTextEdit, QTabWidget
from PySide6.QtGui import QDoubleValidator, QIcon, QPixmap
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

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
        self.message_label = QLabel('Message')
        self.encryption_layout.addWidget(self.message_label)
        self.message_text = QTextEdit()
        self.encryption_layout.addWidget(self.message_text)

        self.key_label = QLabel('Key')
        self.encryption_layout.addWidget(self.key_label)
        self.key_line = QLineEdit()
        self.encryption_layout.addWidget(self.key_line)

        self.iv_label = QLabel('IV')
        self.encryption_layout.addWidget(self.iv_label)
        self.iv_line = QLineEdit()
        self.iv_line.setReadOnly(True)
        self.encryption_layout.addWidget(self.iv_line)

        self.cipher_label = QLabel('Cipher')
        self.encryption_layout.addWidget(self.cipher_label)
        self.cipher_text = QTextEdit()
        self.cipher_text.setReadOnly(True)
        self.encryption_layout.addWidget(self.cipher_text)

        self.encryption_send_button = QPushButton('Encrypt Message')
        self.encryption_layout.addWidget(self.encryption_send_button)

        self.encryption_error_label = QLabel()
        self.encryption_layout.addWidget(self.encryption_error_label)


        # Decryption page
        self.decryption_page = QWidget()
        self.decryption_layout = QVBoxLayout()
        self.decryption_page.setLayout(self.decryption_layout)

        self.dec_label = QLabel('DECRYPTION')
        self.decryption_layout.addWidget(self.dec_label)

        # Tab widgets
        self.tab_bar = QTabWidget()
        self.tab_bar.addTab(self.encryption_page, 'Encryption')
        self.tab_bar.addTab(self.decryption_page, 'Decryption')
        self.central_layout.addWidget(self.tab_bar)

if __name__ == '__main__':

    app = QApplication()

    window = MainWindow()

    window.show()
    app.exec()
