#RSA
#server

import socket
import rsa

def generate_keys():
    public_key, private_key = rsa.newkeys(512)
    return public_key, private_key

def rsa_decrypt(ciphertext, private_key):
    decrypted_message = rsa.decrypt(ciphertext, private_key).decode()
    return decrypted_message

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)

print("Server is listening...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Generate RSA keys
public_key, private_key = generate_keys()

# Send the public key to the client
conn.send(public_key.save_pkcs1())

# Receive the encrypted message from the client
ciphertext = conn.recv(1024)

# Decrypt the message
decrypted_message = rsa_decrypt(ciphertext, private_key)
print(f"Decrypted message from client: {decrypted_message}")

conn.close()
server_socket.close()


#client

import socket
import rsa

def rsa_encrypt(plaintext, public_key):
    encrypted_message = rsa.encrypt(plaintext.encode(), public_key)
    return encrypted_message

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

# Receive the public key from the server
public_key_data = client_socket.recv(1024)

# Load the public key
public_key = rsa.PublicKey.load_pkcs1(public_key_data)

# Message to send
plaintext = "This is a secret message from the client."

# Encrypt the message using the server's public key
ciphertext = rsa_encrypt(plaintext, public_key)

# Send the encrypted message to the server
client_socket.send(ciphertext)

client_socket.close()


#AES 
#server
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def unpad(padded_plaintext, block_size=128):
    unpadder = padding.PKCS7(block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def aes_decrypt(ciphertext, key, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)
    return plaintext

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)

print("Server is listening...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive the key and IV
key = conn.recv(32)
iv = conn.recv(16)

# Receive the encrypted message from the client
ciphertext = conn.recv(1024)

# Decrypt the message
decrypted_message = aes_decrypt(ciphertext, key, modes.CBC(iv))
print(f"Decrypted message from client: {decrypted_message.decode('utf-8')}")

conn.close()
server_socket.close()


#client
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def pad(plaintext, block_size=128):
    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return padded_data

def aes_encrypt(plaintext, key, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

# Generate a random key and IV
key = os.urandom(32)
iv = os.urandom(16)

# Message to send
plaintext = b'This is a secret message from the client.'

# Encrypt the message using AES in CBC mode
ciphertext = aes_encrypt(plaintext, key, modes.CBC(iv))

# Send the key, IV, and ciphertext to the server
client_socket.sendall(key)
client_socket.sendall(iv)
client_socket.sendall(ciphertext)

client_socket.close()
