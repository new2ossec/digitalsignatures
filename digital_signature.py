#Importing necessary modules
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib

def calculateHash(message):
    m = hashlib.sha256()
    m.update(message)
    return m.digest()


def checkIntegrity(calculated_hash, decrypted_hash):
    if calculated_hash == decrypted_hash:
        print("The message is valid")
    else:
        print("The message has been tampered with")

class SignedMessage:
    message :bytes = None
    digitalsignature :bytes = None

    def __init__(self, message: bytes):
        self.message = message

    def _hash_message(self):
        # Generate the hash of this message
        return calculateHash(self.message)
        
    def encrypt(self, key):
        hash = self._hash_message()
        #Instantiating PKCS1_OAEP object with the public key for encryption
        cipher = PKCS1_OAEP.new(key=key)
        #Encrypting the message with the PKCS1_OAEP object
        self.digitalsignature = cipher.encrypt(hash)

#The message to be encrypted
message = b'This is the message to be checked for integrity'

msg = SignedMessage(message=message)


#Generating private key (RsaKey object) of key length of 1024 bits
private_key = RSA.generate(1024)
#Generating the public key (RsaKey object) from the private key
public_key = private_key.publickey()


# Calculating the digital signature
msg.encrypt(key = public_key)
print(f"Digital Signature: {msg.digitalsignature}")

# The message is still clear
print(f"Message: {msg.message}")

#Instantiating PKCS1_OAEP object with the private key for decryption
decrypt = PKCS1_OAEP.new(key=private_key)
#Decrypting the message with the PKCS1_OAEP object
decrypted_message = decrypt.decrypt(msg.digitalsignature)

# We recalculate the hash of the message using the same hash function
calcHash = calculateHash(msg.message)

checkIntegrity(calcHash, decrypted_message)
