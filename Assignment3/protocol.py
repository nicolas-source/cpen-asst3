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
        self.parameters_DH = None
        self.private_key = None
        self.public_key = None
        self.session_key = None
        pass

    # Helper functions
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

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC 
    def IsMessagePartOfProtocol(self, message):
        # assume users don't send regular messages in the format of the protocol
        # because if it is recognized as part of the protocol, it will be processed
        print("checking if part of protocol")
        print(self.GetProtocolMessageType(message))
        return self.GetProtocolMessageType(message) in [1,2,3]


    # Contactor: Sends PARAMETERS + PUBLIC KEY
    # Contactor: Creates SHARED KEY from own PRIVATE KEY and Contactee's PUBLIC KEY

    def Exchange_DH_Generate_Keys_B(self):
        self.parameters_DH = dh.generate_parameters(generator=2, key_size=512)
        self.private_key = self.parameters_DH.generate_private_key()
        self.public_key = self.private_key.public_key()
    
    def Exchange_DH_Send_Components_B(self):
        return self.parameters_DH, self.public_key

    def Exchange_DH_create_shared_key_B(self, other_public_key):
        self.shared_key = self.private_key.exchange(other_public_key)


    # Contactee: RECEIVES PARAMETERS then generates PRIVATE & PUBLIC KEY PAIR
    # Contactee: Creates SHARED KEY from own PRIVATE KEY and Contactor's PUBLIC KEY
    def Exchange_DH_Generate_Keys_A(self, parameters_DH):
        self.parameters_DH = parameters_DH
        self.private_key = self.parameters_DH.generate_private_key()
        self.public_key = self.private_key.public_key()
    
    def Exchange_DH_create_shared_key_A(self, other_public_key):
        self.shared_key = self.private_key.exchange(other_public_key)




    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, username, message, shared_secret):
        print("Processing message")
        protocolMessageType = self.GetProtocolMessageType(message)
        parsed_message = None
        try:
            parsed_message = json.loads(message)
        except json.JSONDecodeError:
            return -1
        print("Parsed message: ", parsed_message)
        # handles first message in the protocol
        if (protocolMessageType == 1):
            parsed_message = json.loads(message)
            self.Exchange_DH_Generate_Keys_B()
            # Challenge
            RB =  b64encode(os.urandom(32)).decode('utf-8') + str(time.time())
            # Encrypt user name, RA, DH parameters, and DH public key
            iv = os.urandom(16)
            print("128")
            cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv))
            encryptor = cipher.encryptor()
            raw = {
                "username": username,
                "RA": parsed_message["RA"],
                "DH_parameters": self.parameters_DH,
                "DH_public_key": self.public_key
            }
            print(raw)
            encryptedMessage = encryptor.update(bytes(json.dump(raw), 'utf-8')) + encryptor.finalize()
            res = {}
            res["RB"] = RB
            res["encrypted"] = encryptedMessage
            return json.dumps(res)

        # handles second message in the protocol
        elif (protocolMessageType == 2):
            parsed_message = json.loads(message)

        # handles third message in the protocol
        elif (protocolMessageType == 3):
            parsed_message = json.loads(message)

        else:
            return {
                "error": "Message is not part of the protocol"
            }
        # self.SetSessionKey() # [todo] need key
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(key)       
        self.session_key = derived_key

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(plain_text, 'utf-8')) + encryptor.finalize()
        
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text

        cipher = Cipher(algorithms.AES(self.session), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decryptor.update(ct) + decryptor.finalize()


        return plain_text
