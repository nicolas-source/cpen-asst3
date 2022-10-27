import json
import time
import random


# module for random num gen
# https://cryptography.io/en/latest/random-numbers/
import os
from base64 import b64encode

# cryptography modules for EDH
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# cryptography modules for AES
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()
# ^ demo code



class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.parameters_DH = None
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, username):
        RA =  b64encode(os.urandom(32)).decode('utf-8') + str(time.time()) # random integer + current time as nonce
        message_object = {
            "username": username,
            "RA": RA
        }
        initiation_message = json.dumps(message_object)
        return initiation_message

    # checking if a message is part of protocol and determine which part of the protocol 
    def GetProtocolMessageType(self, message):
        parsed_message = None
        try:
            parsed_message = json.loads(message)
        except json.JSONDecodeError:
            return -1
        
        # First message sent from A to B is the username and RA
        if (parsed_message["username"] is not None and parsed_message["RA"] is not None):
            return 1

        # Second message is RB and {B's username, RA, g, p, g^b mod p}Kab
        if (parsed_message["RB"] is not None and parsed_message["encrypted"] is not None):
            return 2
        
        # Third message is {A's username, RB, g^a mod p}Kab
        if (parsed_message["encrypted"] is not None):
            return 3

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    
    def IsMessagePartOfProtocol(self, message):
        # assume users don't send regular messages in the format of the protocol
        # because if it is recognized as part of the protocol, it will be processed
        return self.GetProtocolMessageType(message) in [1,2,3]


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # need checks to tell us which message in the protocol we are dealing with 
        # handles first message in the protocol

        # handles second message in the protocol

        # handles third message in the protocol
        # self.SetSessionKey() # [todo] need key
        pass

    # For asym key exchange will need to merge into one
    def Exchange_DH_Generate(self):
        self.parameters_DH = dh.generate_parameters(generator=2, key_size=512)
        self.private_key = self.parameters_DH.generate_private_key()
        self.public_key = self.parameters_DH.generate_private_key().public_key()
        pass

    def DH_get_public_key(self):
        return self.public_key
    
    # For asym key exchange will need to merge into one
    def Exchange_DH_Receive():
        parameters = dh.generate_parameters(generator=2, key_size=512)
        private_key = parameters.generate_private_key()
        public_key = parameters.generate_private_key().public_key()
        pass

    def Exchange_DH_create_shared_key(self, peers_public_key):
        self.shared_key = self.private_key.exchange(peers_public_key)
        return self.shared_key


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key

        # TODO: do key derivation

        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
