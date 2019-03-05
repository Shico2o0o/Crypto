# Crypto

A simple app to encrypt and decrypt text files.

# Description:
The app has 3 modes:
1. With no checkbox selected
2. Morse Code (The English alphanumerals are available with some other special charaters like: ,.?!'"()&:)
3. Binary Encryption (Asks for a password with which the text can be encrypted and decrypted)

* Note: the encryption and decryption buttons copies the modified text automatically to your clipboard.
* Note: the text files created by the app are UTF-8 encoded.

# Dependecies:
  * For the GUI:
    * PyQt5
    * pyperclip
    * chardet
  * For the encryption:
    * base64
    * cryptography
  * For the CLI:
    * argparse (Note: it's unfinished, supports only one mode of encryption. Can be found in the simple_encryption.py file.)
