import socket
import threading

# Penyimpanan public key
public_keys = {}

def handle_client(conn, addr):
    while True:
        # Terima request
        data = conn.recv(1024).decode()
        if not data:
            break

        command, identifier, *key_data = data.split(' ')
        if command == "REGISTER":
            # Simpan public key
            public_keys[identifier] = ' '.join(key_data)
            conn.send("Public Key Registered".encode())
        elif command == "GET":
            # Kirim public key
            key = public_keys.get(identifier, "Public Key Not Found")
            conn.send(key.encode())
    conn.close()

def start_pka():
    host = "127.0.0.1"
    port = 7000
    server = socket.socket()
    server.bind((host, port))
    server.listen(5)
    print("PKA is running...")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_pka()
