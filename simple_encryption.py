# import pyperclip
class BinaryEncryption:
    import base64
    import os
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet, InvalidToken

    __salt = 'saltIsSalty'.encode()

    @staticmethod
    def encrypt(textToEncrypt: str, password: str) -> str:
        """
        Takes a string and a password, and returns an encrypted string using the given password.
        """

        textToEncrypt = textToEncrypt.encode()
        password = password.encode()
        kdf = BinaryEncryption.PBKDF2HMAC(
            algorithm=BinaryEncryption.hashes.SHA256(),
            length=32,
            salt=BinaryEncryption.__salt,
            iterations=100000,
            backend=BinaryEncryption.default_backend()
        )
        key = BinaryEncryption.base64.urlsafe_b64encode(kdf.derive(password))
        fernet = BinaryEncryption.Fernet(key)

        return fernet.encrypt(textToEncrypt).decode()

    @staticmethod
    def decrypt(textToDecrypt: str, password: str) -> str:
        """
        Takes an encrypted string and a password, and returns a decrypted string using the given password.
        """

        textToDecrypt = textToDecrypt.encode()
        password = password.encode()
        kdf = BinaryEncryption.PBKDF2HMAC(
            algorithm=BinaryEncryption.hashes.SHA256(),
            length=32,
            salt=BinaryEncryption.__salt,
            iterations=100000,
            backend=BinaryEncryption.default_backend()
        )
        key = BinaryEncryption.base64.urlsafe_b64encode(kdf.derive(password))
        fernet = BinaryEncryption.Fernet(key)
        try:
            decryptedText = fernet.decrypt(textToDecrypt)

        except BinaryEncryption.InvalidToken:
            raise BinaryEncryption.InvalidToken('Wrong password.')

        return decryptedText.decode()


class MorseCode:
    TextToMorseDict = {'A': '.-', 'B': '-...',
                       'C': '-.-.', 'D': '-..', 'E': '.',
                       'F': '..-.', 'G': '--.', 'H': '....',
                       'I': '..', 'J': '.---', 'K': '-.-',
                       'L': '.-..', 'M': '--', 'N': '-.',
                       'O': '---', 'P': '.--.', 'Q': '--.-',
                       'R': '.-.', 'S': '...', 'T': '-',
                       'U': '..-', 'V': '...-', 'W': '.--',
                       'X': '-..-', 'Y': '-.--', 'Z': '--..',
                       '1': '.----', '2': '..---', '3': '...--',
                       '4': '....-', '5': '.....', '6': '-....',
                       '7': '--...', '8': '---..', '9': '----.',
                       '0': '-----', ' ': '   ', r'\n': r'\n',
                       ',': '--..--', '.': '.-.-.-', '&': '.-...',
                       '?': '..--..', '/': '-..-.', '-': '-....-',
                       '(': '-.--.', ')': '-.--.-', '!': '−·−·−−',
                       '\'': '.----.', '@': '.--.-.', ':': '---...',
                       '-': '-....-', '"': '.-..-.'}

    MorseToTextDict = {v:k for k, v in TextToMorseDict.items()}

    @staticmethod
    def cipher(textToMorse: str) -> str:
        """
        Takes a string, and returns a string into Morse Code. Avaliable characters: ?!()/,-.
        """

        textInMorse = []
        for line in textToMorse.upper().split('\n'):
            for word in line.split(' '):
                for letter in word:
                    try:
                        textInMorse.append(MorseCode.TextToMorseDict[letter])

                    except KeyError:
                        raise KeyError('Found a strange character.')

                    textInMorse.append(' ')

                if word:
                    textInMorse.pop()

                textInMorse.append('   ')

            if line:
                textInMorse.pop() * 3

            textInMorse.append('\n')

        textInMorse.pop()

        return ''.join(textInMorse)

    @staticmethod
    def decipher(morseToText: str) -> str:
        """
        Takes a morse code as a string, and returns it in normal text.
        """

        morseInText = []

        for line in morseToText.split('\n'):
            for word in line.split('   '):
                for letter in word.split(' '):
                    if letter:
                        try:
                            morseInText.append(MorseCode.MorseToTextDict[letter])

                        except KeyError:
                            raise KeyError('Found a strange character.')

                morseInText.append(' ')

            morseInText.pop()
            morseInText.append('\n')

        morseInText.pop()

        return ''.join(morseInText)


def encrypt(textToEncrypt: str) -> str:
    """
    Takes a string a returns it encrypted.
    """

    encryptedTextList = []

    for letter in textToEncrypt[1:]:
        if letter == ' ' or letter == '\n':
            encryptedTextList.append(letter)

        else:
            encryptedTextList.append(chr(ord(letter) + 1))

    encryptedTextList.append(chr(ord(textToEncrypt[0]) + 1))

    encryptedText = ''.join(encryptedTextList)

    # Uncomment the line below to add the encrypted text to the user's clipboard
    # pyperclip.copy(cypheredText)

    return encryptedText

def decrypt(textToDecrypt: str) -> str:
    """
    Takes encrypted string and returns a decrypted string.
    """

    decryptedTextList = []

    decryptedTextList.append(chr(ord(textToDecrypt[-1]) - 1))

    for letter in textToDecrypt[:-1]:
        if letter == ' ' or letter == '\n':
            decryptedTextList.append(letter)

        else:
            decryptedTextList.append(chr(ord(letter) - 1))

    decryptedText = ''.join(decryptedTextList)

    # Uncomment the line below to add the decrypted text to the user's clipboard
    # pyperclip.copy(decryptedText)

    return decryptedText

def main():
    import sys
    args = sys.argv[1:]

    if args:
        import argparse

        def commandLineInterface():
            parser = argparse.ArgumentParser(description='Simple encryptor and decryptor.', prog='Crypto')

            parser.add_argument('-e', '--encrypt',
                                    action='store_true',
                                    help = 'Creates an encrypted copy of the destined file.')

            parser.add_argument('-d', '--decrypt',
                                    action='store_true',
                                    help = 'Creates a decrypted copy of the destined file.')

            parser.add_argument('file',
                                        type=str,
                                        help='Enter the file\'s name')


            args = parser.parse_args()


            choice = ''

            if args.encrypt:
                text = open(args.file, 'r')
                choice = 'Encrypted'
                encryptedFile = open(args.file[:-4] + choice + '.txt', 'w')
                encryptedFile.write(encrypt(text.read()))
                text.close()
                encryptedFile.close()

            if args.decrypt:
                text = open(args.file, 'r')
                choice = 'Decrypted'
                decryptedFile = open(args.file[:-4] + choice + '.txt', 'w')
                decryptedFile.write(decrypt(text.read()))
                text.close()
                decryptedFile.close()

        commandLineInterface()

    else:
        def mainRun():
            while True:
                while True:
                    mode = input("Enter 'e' to encrypt, 'd' to decrypt: ")

                    if mode[0].lower() == 'e':
                        print('\nEnter text to encrypt:')
                        print('\nEncrypted text:\n' + encrypt(input()) + '\n')
                        break

                    elif mode == 'd':
                        print('\nEnter text to decrypt:')
                        print('\nDecrypted text:\n' + decrypt(input()) + '\n')
                        break

                    else:
                        print('\nPlease follow instructions!\n')


                print('\nAgain? ', end='')

                if input()[0].lower() == 'y':
                    print()
                    continue

                else:
                    sys.exit()

        mainRun()


if __name__ == '__main__':
    main()
