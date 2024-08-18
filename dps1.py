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
