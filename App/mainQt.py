import sys
import MainWindow
import json
import concurrent.futures
import os
from threading import Thread
from CiphModes import *
from Converter import Converter
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtWidgets import QLabel, QProgressBar, QFileDialog, QBoxLayout
from PyQt5.QtCore import Qt
import service


encFolder = os.getcwd() + "/encrypt"
decFolder = os.getcwd() + "/decrypt"


class MyWindow(QMainWindow, MainWindow.Ui_MainWindow):
    # config
    KEY = service.key_to_hex_str('12332243342')
    SPICE = 0x4957df9f02329f2d07289bb61a440e059f9c5dcb93048b5686208a26403c5e7f99ed0051cdb0d7bb8f0c6e4962e43023a0b02b363ffa0b53abf6d3f4f848f5e9
    IV = None
    BLOCKSIZE = 64
    CIPHER = 'encrypt'
    MODE = 'cbc'
    Path = dict()
    Labels = []
    Progresses = []

    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)
        self.vLayout1.setAlignment(Qt.AlignTop)
        self.vLayout2.setAlignment(Qt.AlignTop)
        self.bindSlotSignals()

    def bindSlotSignals(self):
        self.actionExit.triggered.connect(exit)
        self.actionOpen.triggered.connect(self.openFile)
        self.actionFrom_File.triggered.connect(self.setConfig)
        self.actionEncrypt.triggered.connect(self.encrypt)
        self.actionDecrypt.triggered.connect(self.decrypt)
        self.actionClear.triggered.connect(self.clear)

    def clear(self):
        for widget in self.Labels:
            self.vLayout1.removeWidget(widget)
            widget.hide()

        for widget in self.Progresses:
            self.vLayout2.removeWidget(widget)
            widget.hide()

        # clear all prepared files
        self.Path.clear()
        self.Labels.clear()
        self.Progresses.clear()

    def openFile(self):
        fileNames = QFileDialog().getOpenFileNames(self, "Open Files", "/home/slon/Project/cripta/HPCkurs/App")[0]

        if len(fileNames) == 0:
            return

        for fname in fileNames:
            # Gui add
            label = QLabel(self)
            label.setText(fname.split('/')[-1])
            progress = QProgressBar()
            progress.setFixedHeight(18)
            self.vLayout1.addWidget(label)
            self.vLayout2.addWidget(progress)

            # for future delete
            self.Labels.append(label)
            self.Progresses.append(progress)

            # add to Path
            self.Path[fname] = progress

    def setConfig(self):
        name = QFileDialog().getOpenFileName(self, "Open Json File", "/home/slon/Project/cripta/HPCkurs/App",
                                             "Json (*.json)")[0]

        if len(name) == 0:
            return

        data = ''
        with open(name, 'r') as f:
            data = f.read()

        data = json.loads(data)

        if data['iv'] == "none":
            self.IV = None
        else:
            if (len(data['iv'][2:]) // 2) != (int(data['blocksize']) // 8):
                self.IV = '0x' + '1' * (2 * int(data['blocksize']) // 8)
            else:
                self.IV = data['iv']

        self.KEY = service.key_to_hex_str(data['key'])
        self.SPICE = int(data['spice'], 16)
        self.BLOCKSIZE = int(data['blocksize'])
        # self.CIPHER = data['cipher']
        self.MODE = data['mode']

    def encrypt(self):
        self.CIPHER = 'encrypt'
        thread = Thread(target=self.start)
        thread.start()

    def decrypt(self):
        self.CIPHER = 'decrypt'
        thread = Thread(target=self.start)
        thread.start()

    def start(self):
        copyPath = list(self.Path.copy().keys())  # потому что удаляем из Path в HPCstart

        if len(copyPath) == 0:
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(copyPath)) as executor:
            for fname in copyPath:
                executor.submit(self.HPCstart, fname, self.Path[fname])

    def HPCstart(self, fname: str, progress: QProgressBar):
        data = b''
        res = b''

        with open(fname, 'rb') as f:
            data = f.read()

        if self.CIPHER == 'encrypt':
            if self.MODE == 'ecb':
                res = ECB_encrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE), self.KEY, self.SPICE,
                                  progress)
            elif self.MODE == 'cbc':
                res = CBC_encrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE), self.KEY, self.SPICE, self.IV,
                                  progress)
            elif self.MODE == 'cfb':
                res = CFB_encrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE), self.KEY, self.SPICE, self.IV,
                                  progress)
            elif self.MODE == 'ofb':
                res = OFB_encrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE), self.KEY, self.SPICE, self.IV,
                                  progress)

            with open(encFolder + '/' + fname.split('/')[-1], 'wb') as f:
                f.write(Converter.hex_to_bytes(res, useLastBlock=False))

        elif self.CIPHER == 'decrypt':
            if self.MODE == 'ecb':
                res = ECB_decrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE, useLastBlock=False), self.KEY,
                                  self.SPICE, progress)
            elif self.MODE == 'cbc':
                res = CBC_decrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE, useLastBlock=False), self.KEY,
                                  self.SPICE, self.IV, progress)
            elif self.MODE == 'cfb':
                res = CFB_decrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE, useLastBlock=False), self.KEY,
                                  self.SPICE, self.IV, progress)
            elif self.MODE == 'ofb':
                res = OFB_decrypt(Converter.bytes_to_hex_list(data, self.BLOCKSIZE, useLastBlock=False), self.KEY,
                                  self.SPICE, self.IV, progress)

            with open(decFolder + '/' + fname.split('/')[-1], 'wb') as f:
                f.write(Converter.hex_to_bytes(res))
        else:
            raise ValueError('wrong cipher')

        # удаляем из списка путей для необработанных файлов
        # self.Path.pop(self.Path.index(fname))
        self.Path.pop(fname)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())
