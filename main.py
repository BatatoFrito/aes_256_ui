'''

This application is an AES encryption/decryption tool with an UI

'''

import base64
from PySide6.QtCore import QSize, Qt, Slot
from PySide6.QtWidgets import QApplication, QPushButton, QWidget, QGridLayout, QMainWindow, QLineEdit, QVBoxLayout, QLabel, QDialog
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
        self.central_layout.setAlignment(Qt.AlignTop)

if __name__ == '__main__':

    app = QApplication()

    window = MainWindow()

    window.show()
    app.exec()
