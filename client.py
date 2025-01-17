import socket
from Crypto.PublicKey import RSA # pip install pycryptodome
from Crypto.Cipher import PKCS1_OAEP # pip install pycryptodome
import os
import base64

def generate_keys(private_key_file, public_key_file):
    if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
        key = RSA.generate(2048)
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(key.export_key())
        with open(public_key_file, "wb") as pub_file:
            pub_file.write(key.publickey().export_key())

def load_keys(private_key_file, public_key_file):
    with open(private_key_file, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    with open(public_key_file, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    return private_key, public_key

def main():
    private_key_file = "client_private_key.pem"
    public_key_file = "client_public_key.pem"

    # Генерация или загрузка ключей
    generate_keys(private_key_file, public_key_file)
    client_private_key, client_public_key = load_keys(private_key_file, public_key_file)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 8080))

    # Отправляем открытый ключ клиента серверу
    client_socket.send(base64.b64encode(client_public_key.export_key()))

    # Получаем открытый ключ сервера
    server_public_key_data = base64.b64decode(client_socket.recv(2048))
    server_public_key = RSA.import_key(server_public_key_data)

    # Отправляем зашифрованное сообщение серверу
    message = "Привет, сервер!".encode()
    cipher_with_client_private = PKCS1_OAEP.new(client_private_key)
    partially_encrypted_message = cipher_with_client_private.encrypt(message)

    cipher_with_server_public = PKCS1_OAEP.new(server_public_key)
    fully_encrypted_message = cipher_with_server_public.encrypt(partially_encrypted_message)

    client_socket.send(fully_encrypted_message)

    # Получаем зашифрованный ответ от сервера
    encrypted_response = client_socket.recv(2048)
    cipher_with_server_public = PKCS1_OAEP.new(server_public_key)
    partially_decrypted_response = cipher_with_server_public.decrypt(encrypted_response)

    cipher_with_client_private = PKCS1_OAEP.new(client_private_key)
    fully_decrypted_response = cipher_with_client_private.decrypt(partially_decrypted_response)

    print(f"Ответ от сервера: {fully_decrypted_response.decode()}")

    client_socket.close()

if __name__ == "__main__":
    main()