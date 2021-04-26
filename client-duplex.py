import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
from base64 import b64encode


# Generating public and private keys

keyPair = RSA.generate(1024)
pubKey = keyPair.publickey()
pubKeyPEM = pubKey.exportKey()
privKeyPEM = keyPair.exportKey()

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1100))


# Testing connection
from_server = s.recv(4096)
print ("Recieved from server: ",from_server.decode("ascii"))

# Sending public key
s.send(pubKeyPEM)

# Receiving encrypted AES session key
from_server = s.recv(4096)
session_key = from_server

# Deciphering session key using private key
print("Recieved from server the encrypted session key")
print("Decrypting...")
decryptor = PKCS1_OAEP.new(keyPair)
decrypted_session_key = decryptor.decrypt(session_key)

# Sending some information using AES session key
information = b'This is homework 8 complete!'
print("Message: ", information)
print('Encrypting message with key:', b64encode(decrypted_session_key).decode('utf-8'))
cipher = AES.new(decrypted_session_key, AES.MODE_EAX)
ciphertext = cipher.encrypt(information)
nonce = cipher.nonce

print("Sending encrypted message: ", b64encode(nonce + ciphertext).decode('utf-8'))
s.send(nonce + ciphertext)


s.send(b'Hello again')

'''
data=s.send(b'Hola XYZ Message')
s.close()
'''