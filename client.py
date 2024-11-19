import socket
from des_cli import encryption_large_text, decryption_large_text, generate_random_key
from rsa_util_manual import rsa_encrypt

def client_program():
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))
    encryption = encryption_large_text
    decryption = decryption_large_text
    randomkey = generate_random_key

    # Receive public key from server
    public_key_data = client_socket.recv(1024).decode()
    e, n = map(int, public_key_data.split())
    public_key = (e, n)
    print("Public Key received from Server:", public_key)

    while True:
        # Generate DES key and encrypt it using RSA
        des_key = randomkey()
        encrypted_key = rsa_encrypt(public_key, des_key)
        client_socket.send(str(encrypted_key).encode())
        print("Encrypted DES Key sent to Server.")

        # Input message and encrypt
        message = input("Client Message: ")
        if message.lower().strip() == "bye":
            break
        encrypted_message = encryption(message, des_key)
        client_socket.send(encrypted_message.encode())
        print("Message:", message)
        print("Encrypted Message:", encrypted_message)

        # Receive and decrypt server response
        encrypted_response = client_socket.recv(1024).decode()
        if not encrypted_response:
            break
        decrypted_response = decryption(encrypted_response, des_key)
        print("Received Encrypted Response:", encrypted_response)
        print("Decrypted Response:", decrypted_response)

    client_socket.close()

if __name__ == '__main__':
    client_program()
