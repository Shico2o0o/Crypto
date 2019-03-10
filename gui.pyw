from PyQt5 import QtCore, QtGui, QtWidgets
from simple_encryption import decrypt, encrypt, MorseCode, BinaryEncryption
import pyperclip, chardet, os



class QPlainTextEdit(QtWidgets.QPlainTextEdit):

    def mousePressEvent(self, QMouseEvent):
        if self.toPlainText():
            self.selectAll()



class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(763, 574)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(14)
        MainWindow.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(os.path.join('img', 'icon.png')), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setAutoFillBackground(False)
        MainWindow.setStyleSheet("color: rgb(0, 0, 0);")
        MainWindow.setAnimated(True)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(14)
        self.centralwidget.setFont(font)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tabWidget.sizePolicy().hasHeightForWidth())
        self.tabWidget.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(8)
        font.setBold(False)
        font.setWeight(50)
        self.tabWidget.setFont(font)
        self.tabWidget.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.North)
        self.tabWidget.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.tabWidget.setElideMode(QtCore.Qt.ElideNone)
        self.tabWidget.setDocumentMode(False)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setTabBarAutoHide(False)
        self.tabWidget.setObjectName("tabWidget")
        self.textTab = QtWidgets.QWidget()
        self.textTab.setObjectName("textTab")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.textTab)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.groupBoxInput = QtWidgets.QGroupBox(self.textTab)
        self.groupBoxInput.setObjectName("groupBoxInput")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.groupBoxInput)
        self.verticalLayout.setObjectName("verticalLayout")
        self.EnterTextHere = QPlainTextEdit(self.groupBoxInput)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(12)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        font.setStyleStrategy(QtGui.QFont.PreferDefault)
        self.EnterTextHere.setFont(font)
        self.EnterTextHere.setAcceptDrops(True)
        self.EnterTextHere.setAutoFillBackground(False)
        self.EnterTextHere.setStyleSheet("font: 12pt \"Monaco\";")
        self.EnterTextHere.setInputMethodHints(QtCore.Qt.ImhNone)
        self.EnterTextHere.setFrameShape(QtWidgets.QFrame.Box)
        self.EnterTextHere.setTabChangesFocus(True)
        self.EnterTextHere.setOverwriteMode(False)
        self.EnterTextHere.setTextInteractionFlags(QtCore.Qt.TextEditorInteraction)
        self.EnterTextHere.setBackgroundVisible(False)
        self.EnterTextHere.setObjectName("EnterTextHere")
        self.verticalLayout.addWidget(self.EnterTextHere)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.encryptPushButton = QtWidgets.QPushButton(self.groupBoxInput)
        self.encryptPushButton.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Source Code Pro\";")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(os.path.join('img', 'lockIcon.png')), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.encryptPushButton.setIcon(icon1)
        self.encryptPushButton.setIconSize(QtCore.QSize(30, 30))
        self.encryptPushButton.setObjectName("encryptPushButton")
        self.horizontalLayout_2.addWidget(self.encryptPushButton)
        self.decryptPushButton = QtWidgets.QPushButton(self.groupBoxInput)
        self.decryptPushButton.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Source Code Pro\";")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(os.path.join('img', "unlockIcon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.decryptPushButton.setIcon(icon2)
        self.decryptPushButton.setIconSize(QtCore.QSize(30, 30))
        self.decryptPushButton.setObjectName("decryptPushButton")
        self.horizontalLayout_2.addWidget(self.decryptPushButton)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.verticalLayout_4.addWidget(self.groupBoxInput)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.checkBoxMorseCode = QtWidgets.QCheckBox(self.textTab)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(12)
        self.checkBoxMorseCode.setFont(font)
        self.checkBoxMorseCode.setTristate(False)
        self.checkBoxMorseCode.setObjectName("checkBoxMorseCode")
        self.horizontalLayout.addWidget(self.checkBoxMorseCode)
        self.checkBoxBinaryEncryption = QtWidgets.QCheckBox(self.textTab)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(12)
        self.checkBoxBinaryEncryption.setFont(font)
        self.checkBoxBinaryEncryption.setTristate(False)
        self.checkBoxBinaryEncryption.setObjectName("checkBoxBinaryEncryption")
        self.horizontalLayout.addWidget(self.checkBoxBinaryEncryption)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.verticalLayout_4.addLayout(self.horizontalLayout)
        self.groupBoxDecryption = QtWidgets.QGroupBox(self.textTab)
        self.groupBoxDecryption.setEnabled(True)
        self.groupBoxDecryption.setObjectName("groupBoxDecryption")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.groupBoxDecryption)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.showTextHere = QtWidgets.QPlainTextEdit(self.groupBoxDecryption)
        self.showTextHere.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.showTextHere.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.showTextHere.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Monaco\";")
        self.showTextHere.setInputMethodHints(QtCore.Qt.ImhMultiLine|QtCore.Qt.ImhNoPredictiveText)
        self.showTextHere.setFrameShape(QtWidgets.QFrame.Box)
        self.showTextHere.setTabChangesFocus(True)
        self.showTextHere.setUndoRedoEnabled(False)
        self.showTextHere.setReadOnly(True)
        self.showTextHere.setOverwriteMode(False)
        self.showTextHere.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.showTextHere.setBackgroundVisible(False)
        self.showTextHere.setCenterOnScroll(False)
        self.showTextHere.setObjectName("showTextHere")
        self.verticalLayout_3.addWidget(self.showTextHere)
        self.verticalLayout_4.addWidget(self.groupBoxDecryption)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(os.path.join('img', "textIcon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tabWidget.addTab(self.textTab, icon3, "")
        self.fileTab = QtWidgets.QWidget()
        self.fileTab.setObjectName("fileTab")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.fileTab)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.groupBoxInput2 = QtWidgets.QGroupBox(self.fileTab)
        self.groupBoxInput2.setEnabled(True)
        self.groupBoxInput2.setObjectName("groupBoxInput2")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.groupBoxInput2)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.showFilesContents = QtWidgets.QPlainTextEdit(self.groupBoxInput2)
        self.showFilesContents.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.showFilesContents.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Monaco\";")
        self.showFilesContents.setInputMethodHints(QtCore.Qt.ImhMultiLine|QtCore.Qt.ImhNoPredictiveText)
        self.showFilesContents.setFrameShape(QtWidgets.QFrame.Box)
        self.showFilesContents.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.showFilesContents.setTabChangesFocus(True)
        self.showFilesContents.setUndoRedoEnabled(False)
        self.showFilesContents.setReadOnly(False)
        self.showFilesContents.setOverwriteMode(False)
        self.showFilesContents.setTextInteractionFlags(QtCore.Qt.TextEditorInteraction)
        self.showFilesContents.setBackgroundVisible(False)
        self.showFilesContents.setObjectName("showFilesContents")
        self.verticalLayout_5.addWidget(self.showFilesContents)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.pushButtonOpenFile = QtWidgets.QPushButton(self.groupBoxInput2)
        self.pushButtonOpenFile.setStyleSheet("font: 12pt \"Source Code Pro\";")
        self.pushButtonOpenFile.setObjectName("pushButtonOpenFile")
        self.horizontalLayout_4.addWidget(self.pushButtonOpenFile)
        self.pushButtonEncryptFile = QtWidgets.QPushButton(self.groupBoxInput2)
        self.pushButtonEncryptFile.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Source Code Pro\";")
        self.pushButtonEncryptFile.setIcon(icon1)
        self.pushButtonEncryptFile.setIconSize(QtCore.QSize(30, 30))
        self.pushButtonEncryptFile.setObjectName("pushButtonEncryptFile")
        self.horizontalLayout_4.addWidget(self.pushButtonEncryptFile)
        self.pushButtonDecryptFile = QtWidgets.QPushButton(self.groupBoxInput2)
        self.pushButtonDecryptFile.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Source Code Pro\";")
        self.pushButtonDecryptFile.setIcon(icon2)
        self.pushButtonDecryptFile.setIconSize(QtCore.QSize(30, 30))
        self.pushButtonDecryptFile.setObjectName("pushButtonDecryptFile")
        self.horizontalLayout_4.addWidget(self.pushButtonDecryptFile)
        self.verticalLayout_5.addLayout(self.horizontalLayout_4)
        self.verticalLayout_6.addWidget(self.groupBoxInput2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem2)
        self.checkBoxMorseCode_2 = QtWidgets.QCheckBox(self.fileTab)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(12)
        self.checkBoxMorseCode_2.setFont(font)
        self.checkBoxMorseCode_2.setTristate(False)
        self.checkBoxMorseCode_2.setObjectName("checkBoxMorseCode_2")
        self.horizontalLayout_3.addWidget(self.checkBoxMorseCode_2)
        self.checkBoxBinaryEncryption_2 = QtWidgets.QCheckBox(self.fileTab)
        font = QtGui.QFont()
        font.setFamily("Monaco")
        font.setPointSize(12)
        self.checkBoxBinaryEncryption_2.setFont(font)
        self.checkBoxBinaryEncryption_2.setTristate(False)
        self.checkBoxBinaryEncryption_2.setObjectName("checkBoxBinaryEncryption_2")
        self.horizontalLayout_3.addWidget(self.checkBoxBinaryEncryption_2)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem3)
        self.verticalLayout_6.addLayout(self.horizontalLayout_3)
        self.groupBoxOutput2 = QtWidgets.QGroupBox(self.fileTab)
        self.groupBoxOutput2.setEnabled(True)
        self.groupBoxOutput2.setObjectName("groupBoxOutput2")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.groupBoxOutput2)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.showModifiedFilesContents = QtWidgets.QPlainTextEdit(self.groupBoxOutput2)
        self.showModifiedFilesContents.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.showModifiedFilesContents.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.showModifiedFilesContents.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Monaco\";")
        self.showModifiedFilesContents.setInputMethodHints(QtCore.Qt.ImhMultiLine|QtCore.Qt.ImhNoPredictiveText)
        self.showModifiedFilesContents.setFrameShape(QtWidgets.QFrame.Box)
        self.showModifiedFilesContents.setTabChangesFocus(True)
        self.showModifiedFilesContents.setUndoRedoEnabled(False)
        self.showModifiedFilesContents.setReadOnly(True)
        self.showModifiedFilesContents.setOverwriteMode(False)
        self.showModifiedFilesContents.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.showModifiedFilesContents.setBackgroundVisible(False)
        self.showModifiedFilesContents.setObjectName("showModifiedFilesContents")
        self.verticalLayout_9.addWidget(self.showModifiedFilesContents)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.pushButtonSaveToFile = QtWidgets.QPushButton(self.groupBoxOutput2)
        self.pushButtonSaveToFile.setStyleSheet("color: rgb(0, 0, 0);\n""font: 12pt \"Source Code Pro\";")
        self.pushButtonSaveToFile.setObjectName("pushButtonSaveToFile")
        self.horizontalLayout_5.addWidget(self.pushButtonSaveToFile)
        self.verticalLayout_9.addLayout(self.horizontalLayout_5)
        self.verticalLayout_6.addWidget(self.groupBoxOutput2)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(os.path.join('img', 'fileIcon.png')), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tabWidget.addTab(self.fileTab, icon4, "")
        self.verticalLayout_2.addWidget(self.tabWidget)
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.checkBoxMorseCode.toggled['bool'].connect(self.checkBoxBinaryEncryption.setDisabled)
        self.checkBoxBinaryEncryption.toggled['bool'].connect(self.checkBoxMorseCode.setDisabled)
        self.checkBoxMorseCode_2.toggled['bool'].connect(self.checkBoxBinaryEncryption_2.setDisabled)
        self.checkBoxBinaryEncryption_2.toggled['bool'].connect(self.checkBoxMorseCode_2.setDisabled)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        MainWindow.setTabOrder(self.EnterTextHere, self.encryptPushButton)
        MainWindow.setTabOrder(self.encryptPushButton, self.decryptPushButton)
        MainWindow.setTabOrder(self.decryptPushButton, self.checkBoxMorseCode)
        MainWindow.setTabOrder(self.checkBoxMorseCode, self.checkBoxBinaryEncryption)
        MainWindow.setTabOrder(self.checkBoxBinaryEncryption, self.showTextHere)
        MainWindow.setTabOrder(self.showTextHere, self.showModifiedFilesContents)
        MainWindow.setTabOrder(self.showModifiedFilesContents, self.pushButtonOpenFile)
        MainWindow.setTabOrder(self.pushButtonOpenFile, self.pushButtonEncryptFile)
        MainWindow.setTabOrder(self.pushButtonEncryptFile, self.pushButtonDecryptFile)
        MainWindow.setTabOrder(self.pushButtonDecryptFile, self.checkBoxMorseCode_2)
        MainWindow.setTabOrder(self.checkBoxMorseCode_2, self.checkBoxBinaryEncryption_2)
        MainWindow.setTabOrder(self.checkBoxBinaryEncryption_2, self.pushButtonSaveToFile)
        MainWindow.setTabOrder(self.pushButtonSaveToFile, self.showFilesContents)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Crypto"))
        self.groupBoxInput.setTitle(_translate("MainWindow", "Input"))
        self.EnterTextHere.setPlaceholderText(_translate("MainWindow", "Enter text to encrypt here..."))
        self.encryptPushButton.setText(_translate("MainWindow", "Encrypt"))
        self.encryptPushButton.setShortcut(_translate("MainWindow", "Return"))
        self.decryptPushButton.setText(_translate("MainWindow", "Decrypt"))
        self.decryptPushButton.setShortcut(_translate("MainWindow", "Shift+Return"))
        self.checkBoxMorseCode.setText(_translate("MainWindow", "Morse Code"))
        self.checkBoxBinaryEncryption.setText(_translate("MainWindow", "Binary Encryption"))
        self.groupBoxDecryption.setTitle(_translate("MainWindow", "Output"))
        self.showTextHere.setPlaceholderText(_translate("MainWindow", "Your text will be shown here..."))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.textTab), _translate("MainWindow", "Text"))
        self.groupBoxInput2.setTitle(_translate("MainWindow", "Input"))
        self.showFilesContents.setPlaceholderText(_translate("MainWindow", "Your file\'s contents will be shown here..."))
        self.pushButtonOpenFile.setText(_translate("MainWindow", "Open File"))
        self.pushButtonEncryptFile.setText(_translate("MainWindow", "Encrypt"))
        self.pushButtonEncryptFile.setShortcut(_translate("MainWindow", "Return"))
        self.pushButtonDecryptFile.setText(_translate("MainWindow", "Decrypt"))
        self.pushButtonDecryptFile.setShortcut(_translate("MainWindow", "Shift+Return"))
        self.checkBoxMorseCode_2.setText(_translate("MainWindow", "Morse Code"))
        self.checkBoxBinaryEncryption_2.setText(_translate("MainWindow", "Binary Encryption"))
        self.groupBoxOutput2.setTitle(_translate("MainWindow", "Output"))
        self.showModifiedFilesContents.setPlaceholderText(_translate("MainWindow", "Modified text will be shown here..."))
        self.pushButtonSaveToFile.setText(_translate("MainWindow", "Save To File"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.fileTab), _translate("MainWindow", "File"))



class ApplicationWindow(QtWidgets.QMainWindow):

    def __init__(self):


        def encryptAndShow():
            if self.ui.EnterTextHere.toPlainText():
                text = ''
                if self.ui.checkBoxMorseCode.isChecked():
                    try:
                        text = MorseCode.cipher(self.ui.EnterTextHere.toPlainText())

                    except KeyError:
                        self.ui.showTextHere.setPlainText('Strange symbols were entered, please review your input.')
                        return

                elif self.ui.checkBoxBinaryEncryption.isChecked():
                    password, okPressed = QtWidgets.QInputDialog.getText(self, "Enter Password","Password:", QtWidgets.QLineEdit.Password)
                    if okPressed and password != '':
                        text = BinaryEncryption.encrypt(self.ui.EnterTextHere.toPlainText(), password)

                else:
                    text = encrypt(self.ui.EnterTextHere.toPlainText())

                self.ui.showTextHere.setPlainText(text)
                pyperclip.copy(text)

            else:
                self.ui.showTextHere.clear()


        def decryptAndShow():
            if self.ui.EnterTextHere.toPlainText():
                text = ''
                if self.ui.checkBoxMorseCode.isChecked():
                    try:
                        text = MorseCode.decipher(self.ui.EnterTextHere.toPlainText())

                    except KeyError:
                        self.ui.showTextHere.setPlainText('Strange symbols were entered, please review your input.')
                        return

                elif self.ui.checkBoxBinaryEncryption.isChecked():
                    password, okPressed = QtWidgets.QInputDialog.getText(self, "Enter Password","Password:", QtWidgets.QLineEdit.Password)
                    if okPressed and password != '':
                        try:
                            text = BinaryEncryption.decrypt(self.ui.EnterTextHere.toPlainText(), password)

                        except BinaryEncryption.InvalidToken:
                            self.ui.showTextHere.setPlainText('Wrong Password!!!')
                            return

                else:
                    text = decrypt(self.ui.EnterTextHere.toPlainText())

                self.ui.showTextHere.setPlainText(text)
                pyperclip.copy(text)

            else:
                self.ui.showTextHere.clear()


        def openFile():
            filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Select a text file", "", "Text files (*.txt)")
            if filename:
                with open(filename, 'rb') as fileBytes:
                    encoding = chardet.detect(fileBytes.read())['encoding']

                with open(filename, 'rb') as fileHandler:
                    text = fileHandler.read().decode(encoding)

                if encoding != 'utf-8':
                    text = text.encode('utf-8').decode('utf-8')
                self.ui.showFilesContents.setPlainText(text)


        def encryptAndShowFile():
            if self.ui.showFilesContents.toPlainText():
                text = ''
                if self.ui.checkBoxMorseCode_2.isChecked():
                    try:
                        text = MorseCode.cipher(self.ui.showFilesContents.toPlainText())

                    except KeyError:
                        self.ui.showModifiedFilesContents.setPlainText('Strange symbols were entered, please review your input.')
                        return

                elif self.ui.checkBoxBinaryEncryption_2.isChecked():
                    password, okPressed = QtWidgets.QInputDialog.getText(self, "Enter Password","Password:", QtWidgets.QLineEdit.Password)
                    if okPressed and password != '':
                        text = BinaryEncryption.encrypt(self.ui.showFilesContents.toPlainText(), password)

                else:
                    text = encrypt(self.ui.showFilesContents.toPlainText())

                self.ui.showModifiedFilesContents.setPlainText(text)
                pyperclip.copy(text)

            else:
                self.ui.showModifiedFilesContents.clear()


        def decryptAndShowFile():
            if self.ui.showFilesContents.toPlainText():
                text = ''
                if self.ui.checkBoxMorseCode_2.isChecked():
                    try:
                        text = MorseCode.decipher(self.ui.showFilesContents.toPlainText())

                    except KeyError:
                        self.ui.showModifiedFilesContents.setPlainText('Strange symbols were entered, please review your input.')
                        return

                elif self.ui.checkBoxBinaryEncryption_2.isChecked():
                    password, okPressed = QtWidgets.QInputDialog.getText(self, "Enter Password","Password:", QtWidgets.QLineEdit.Password)
                    if okPressed and password != '':
                        try:
                            text = BinaryEncryption.decrypt(self.ui.showFilesContents.toPlainText(), password)

                        except BinaryEncryption.InvalidToken:
                            self.ui.showModifiedFilesContents.setPlainText('Wrong Password!!!')
                            return

                else:
                    text = decrypt(self.ui.showFilesContents.toPlainText())

                self.ui.showModifiedFilesContents.setPlainText(text)
                pyperclip.copy(text)

            else:
                self.ui.showModifiedFilesContents.clear()


        def saveFile():
            if self.ui.showModifiedFilesContents.toPlainText():
                filename, _ = QtWidgets.QFileDialog.getSaveFileName(filter='(*.txt)')
                f = open(filename, 'w', encoding='utf-8')
                f.write(self.ui.showModifiedFilesContents.toPlainText())

                f.close()

            else:
                self.ui.showModifiedFilesContents.setPlainText('Please enter a file and choose an option first!')


        super(ApplicationWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.encryptPushButton.clicked.connect(encryptAndShow)
        self.ui.decryptPushButton.clicked.connect(decryptAndShow)
        self.ui.pushButtonOpenFile.clicked.connect(openFile)
        self.ui.pushButtonEncryptFile.clicked.connect(encryptAndShowFile)
        self.ui.pushButtonDecryptFile.clicked.connect(decryptAndShowFile)
        self.ui.pushButtonSaveToFile.clicked.connect(saveFile)



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = ApplicationWindow()
    MainWindow.show()
    sys.exit(app.exec_())
