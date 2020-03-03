"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Bryce Woods
    Prateek Makhija
    Jason Nguyen
"""

import socket
import os
import hashlib, binascii
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

host = "localhost"
port = 10001

iv = "superbruhmoment!"

rsa_file = open('../id_rsa.pub','r')
public_key = RSA.importKey(rsa_file.read())
rsa_file.close()

# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)

# Generate a cryptographically random AES key
def generate_key():
    return os.urandom(16)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    encryptor = PKCS1_OAEP.new(public_key)
    return encryptor.encrypt(session_key)


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    new_cipher = AES.new(session_key, AES.MODE_CFB, iv.encode('utf-8'))
    return new_cipher.encrypt(pad_message(message).encode('utf-8'))


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    new_cipher = AES.new(session_key, AES.MODE_CFB, iv.encode('utf-8'))
    return new_cipher.decrypt(message).decode('utf-8')


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # Encrypt message and send to server
        encrypted_message = encrypt_message(message, key)
        send_message(sock, encrypted_message)
        # Receive and decrypt response from server
        received_message = receive_message(sock)
        decrypted_message = decrypt_message(received_message, key)


    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
