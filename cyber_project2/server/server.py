"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Bryce Woods
    Prateek Makhija
    Jason Nguyen
"""

import socket
import hashlib
import hashlib, binascii, os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

host = "localhost"
port = 10001

iv = "superbruhmoment!"

rsa_file = open('../id_rsa','r')
server_private_key = RSA.importKey(rsa_file.read())
rsa_file.close()

# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    decryptor = PKCS1_OAEP.new(server_private_key)
    return decryptor.decrypt(session_key)


# Write a function that decrypts a message using the session key
def decrypt_message(message, session_key):
    new_cipher = AES.new(session_key, AES.MODE_CFB, iv.encode('utf-8'))
    return new_cipher.decrypt(message).decode('utf-8')


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    new_cipher = AES.new(session_key, AES.MODE_CFB, iv.encode('utf-8'))
    return new_cipher.encrypt(pad_message(message).encode('utf-8'))


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # Generate the hashed password
                hashed_password = hashlib.sha512((password + line[1]).encode()).hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # Decrypt message from client
                received_message = decrypt_message(ciphertext_message, plaintext_key)

                # Split response from user into the username and password
                user, password = received_message.split()
                print(user)
                if verify_hash(user, password):
                    response = "User Authenticated"
                else:
                    response = "Username/Password Incorrect"

                # Encrypt response to client
                encrypted_response = encrypt_message(response, plaintext_key)

                # Send encrypted response
                send_message(connection, encrypted_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
