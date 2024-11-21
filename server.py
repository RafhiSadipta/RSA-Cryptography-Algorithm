import socket
from des_cli import encryption_large_text, decryption_large_text
from rsa import generate_rsa_keys, rsa_decrypt

def server_program():
    host = socket.gethostname()
    port = 5000
    encryption = encryption_large_text
    decryption = decryption_large_text

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()
    print(public_key, private_key)

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    conn, address = server_socket.accept()
    print("Connection from:", address)

    # Send public key to client
    conn.send(f"{public_key[0]} {public_key[1]}".encode())
    print("Public Key sent to Client.")

    while True:
        # Receive encrypted DES key from client
        encrypted_key = int(conn.recv(1024).decode())
        print("Encrypted Key Received:", encrypted_key)
        if not encrypted_key:
            break
        des_key = rsa_decrypt(private_key, encrypted_key)
        print("Decrypted DES Key:", des_key)

        # Receive encrypted message
        encrypted_data = conn.recv(1024).decode()
        if not encrypted_data:
            break
        decrypted_data = decryption(encrypted_data, des_key)
        print("Received Encrypted Message:", encrypted_data)
        print("Decrypted Message:", decrypted_data)

        # Send response
        response = input("Server Response: ")
        if response.lower().strip() == "bye":
            break
        encrypted_response = encryption(response, des_key)
        conn.send(encrypted_response.encode())
        print("Encrypted Response:", encrypted_response)

    conn.close()

if __name__ == '__main__':
    server_program()
