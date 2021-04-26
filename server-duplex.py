import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from base64 import b64encode
import binascii

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.bind(('127.0.0.1', 1100))
s.listen(1)

while True:
    conn, addr = s.accept()
    # Testing connection
    conn.send(b"I will send key ")
    data = conn.recv(4096)
    if not data:
        break

    # Receiving public key
    print("Public Key From Client")
    clientPublicKey = data.decode("ascii")
    print (clientPublicKey)

    # Generating random AES key
    key = get_random_bytes(16)

    print("Session Key: ", b64encode(key).decode('utf-8'))
    # Ciphering the session key using client's public key
    rpubKey = RSA.import_key(clientPublicKey)
    encryptor = PKCS1_OAEP.new(rpubKey)
    encrypted = encryptor.encrypt(key)

    # Sending ciphered session key
    conn.send(encrypted)

    # Receiving some information
    data = conn.recv(4096)
    print ("Received from client som encrypted message: ",b64encode(data).decode('utf-8'))
    received_nonce = data[:16]
    received_ciphertext = data[16:]
    # Decrypting information using AES session key
    print('Decrypting message with key:', b64encode(key).decode('utf-8'))
    decipher = AES.new(key, AES.MODE_EAX, nonce=received_nonce)
    decrypted = decipher.decrypt(received_ciphertext)
    print("Message: ", decrypted)

    
'''
connection,address=s.accept();
with connection:
    a=connection.recv(1024);
    print(a.decode("ascii"))
    connection.close();
'''