import json
import time
import random


# module for random num gen
# https://cryptography.io/en/latest/random-numbers/
import os
from base64 import b64encode, b64decode

# cryptography modules for EDH
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import cryptography.hazmat.primitives.serialization as serialization

# cryptography modules for AES
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()
# ^ demo code

key = os.urandom(32)
iv = os.urandom(16)

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.parameters_DH = None
        self.private_key = None
        self.public_key = None
        self.public_key_serialized = None
        self.session_key = None
        self.RA = None
        self.RB = None
        self.secure_state = 0 # state corresponds to which message to send in the secure protocol
        pass

    # Helper functions
    # checking if a message is part of protocol and determine which part of the protocol 
    def GetProtocolMessageType(self, message):
        parsed_message = None
        print("=====================================")
        print("getting protocol message type")
        print("{} {}".format(type(message), message))
        try:
            parsed_message = json.loads(message)
            print("parsed : " + str(parsed_message))
        except json.JSONDecodeError:
            print("not json")
            return -1

        # First message sent from A to B is the username and RA
        if ("username" in parsed_message and parsed_message["RA"] is not None):            
            print("message type 1")
            return 1

        # Second message is RB and {B's username, RA, g, p, g^b mod p}Kab
        if ("RB" in parsed_message and parsed_message["encrypted"] is not None):
            print("message type 2")
            return 2
        
        # Third message is {A's username, RB, g^a mod p}Kab
        if ("encrypted" in parsed_message):
            print("message type 3")
            return 3

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, username):
        self.secure_state = 1
        self.RA =  b64encode(os.urandom(32)).decode('utf-8') + str(time.time()) # random integer + current time as nonce
        message_object = {
            "username": username,
            "RA": self.RA
        }
        initiation_message = json.dumps(message_object)
        return initiation_message

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC 
    def IsMessagePartOfProtocol(self, message):
        # assume users don't send regular messages in the format of the protocol
        # because if it is recognized as part of the protocol, it will be processed
        return self.GetProtocolMessageType(message) in [1,2,3]


    # Contactor: Sends PARAMETERS + PUBLIC KEY
    # Contactor: Creates SHARED KEY from own PRIVATE KEY and Contactee's PUBLIC KEY

    def Exchange_DH_Generate_Keys_B(self):
        # serializing the DH parameters to bytes for sending across the internet 
        parameters_DH = dh.generate_parameters(generator=2, key_size=512)
        self.parameters_DH = parameters_DH.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3).decode('utf-8')
        self.private_key = parameters_DH.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.public_key_serialized = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    def Exchange_DH_compute_shared_key_B(self, other_public_key):
        self.shared_key = self.private_key.exchange(other_public_key)


    # Contactee: RECEIVES PARAMETERS then generates PRIVATE & PUBLIC KEY PAIR
    # Contactee: Creates SHARED KEY from own PRIVATE KEY and Contactor's PUBLIC KEY
    def Exchange_DH_Generate_Keys_A(self, parameters_DH):
        print("114")
        self.parameters_DH = serialization.load_pem_parameters(parameters_DH)
        print("115")
        self.private_key = self.parameters_DH.generate_private_key()
        print("117")
        self.public_key = self.private_key.public_key()
        print("119")
        self.public_key_serialized = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        print("121")
    
    def Exchange_DH_compute_shared_key_A(self, other_public_key):
        self.shared_key = self.private_key.exchange(other_public_key)



    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, username, message, shared_secret):
        protocolMessageType = self.GetProtocolMessageType(message)
        print("Processing protocol message type " + str(protocolMessageType))
        
        parsed_message = None
        try:
            parsed_message = json.loads(message)
        except json.JSONDecodeError:
            return -1
        print("Parsed protocol message: ", parsed_message)

        # generates fixed size shared secret key
        shared_secret_16_char = None
        if len(shared_secret.get()) > 16:
            shared_secret_16_char = shared_secret.get()[0:16]
        else:
            shared_secret_16_char = shared_secret.get().zfill(16)
        
        # handles first message in the protocol
        if (protocolMessageType == 1 and self.secure_state == 0):
            self.secure_state = 2
            parsed_message = json.loads(message)
            # generate DH key pairs
            self.Exchange_DH_Generate_Keys_B()
            # Challenge
            self.RB =  b64encode(os.urandom(32)).decode('utf-8') + str(time.time())
            # Encrypt user name, RA, DH parameters, and DH public key
            iv = os.urandom(16) # TODO do we need to send the IV 
            # IMPORTANT NOTE: Pad with zeros or trim the shared secret key string to be 16 character long
            # so that with utf-8 encoding it will become a 16 byte long key for AES
            cipher = Cipher(algorithms.AES(bytes(shared_secret_16_char, 'utf-8')), modes.CTR(iv))
            encryptor = cipher.encryptor()
            raw = {
                "username": username,
                "RA": parsed_message["RA"],
                "DH_parameters": self.parameters_DH,
                "DH_public_key": self.public_key_serialized
            }
            encryptedMessage = encryptor.update(bytes(json.dumps(raw), 'utf-8')) + encryptor.finalize()
            res = {}
            res["RB"] = self.RB
            res["encrypted"] = b64encode(encryptedMessage).decode('utf-8')
            res["iv"] = b64encode(iv).decode('utf-8')
            return json.dumps(res)

        # handles second message in the protocol
        elif (protocolMessageType == 2 and self.secure_state == 1):
            parsed_message = json.loads(message)
            cipher_text = b64decode(bytes(parsed_message['encrypted'], 'utf-8'))
            iv = b64decode(bytes(parsed_message['iv'], 'utf-8'))

            # decrypt the encrypted part of the message
            cipher = Cipher(algorithms.AES(bytes(shared_secret_16_char, 'utf-8')), modes.CTR(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(cipher_text) + decryptor.finalize()
            raw = json.loads(decrypted)
            
            # verify RA was sent back correctly
            if raw['RA'] != self.RA:
              return {
                "error": "Incorrect RA value, closing down secure connection"
              }
            self.secure_state = 3
            # get the DH parameters and compute shared key
            print(str(raw['DH_parameters']))
            self.Exchange_DH_Generate_Keys_A(raw['DH_parameters'])
            print("195")
            self.Exchange_DH_compute_shared_key_A(raw['DH_public_key'])
            print("197")

            # set the session key
            self.SetSessionKey(self.shared_key)  
            print("201") 

            # generates the third message
            print("generates the third message in the protocol")
            raw = {
                "username": username,
                "RB": parsed_message["RB"],
                "DH_public_key": self.public_key_serialized
            }
            encryptedMessage = encryptor.update(bytes(json.dumps(raw), 'utf-8')) + encryptor.finalize()
            res = {}
            res["encrypted"] = str(encryptedMessage)
            return json.dumps(res)

        # handles third message in the protocol
        elif (protocolMessageType == 3 and self.secure_state == 2):
            parsed_message = json.loads(message)
            plainMessage = parsed_message['encrypted']

            # decrypt the encrypted part of the message
            cipher = Cipher(algorithms.AES(bytes(shared_secret_16_char, 'utf-8')), modes.CTR(iv))
            decryptor = cipher.decryptor()
            decryptor.update(bytes(plainMessage, 'utf-8')) + decryptor.finalize()
            raw = json.loads(plainMessage)

             # verify RB was sent back correctly
            if raw['RB'] != self.RB:
              # TODO is returning here correct?
              return {
                "error": "Incorrect RB value, closing down secure connection"
              }

            # computes shared key
            self.Exchange_DH_compute_shared_key_B(raw['DH_public_key'])
            print('secure channel established')       
            self.SetSessionKey(self.shared_key)    
            print('session key computed')
            return None

        else:
            return {
                "error": "Message is not part of the protocol"
            }


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
        # TODO: what key do we use to compute HMAC?
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(bytes(plain_text, 'utf-8')) + encryptor.finalize()
        
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text

        cipher = Cipher(algorithms.AES(self.session_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decryptor.update(cipher_text) + decryptor.finalize()


        return plain_text
