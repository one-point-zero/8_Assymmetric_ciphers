import socket
from Crypto.PublicKey import RSA # pip install pycryptodome
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os

# Функция для генерации пары ключей RSA и сохранения их в файлы
def generate_keys(private_key_file, public_key_file):
    if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
        key = RSA.generate(2048) # Генерируем ключ длиной 2048 бит
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(key.export_key()) # Сохраняем закрытый ключ
        with open(public_key_file, "wb") as pub_file:
            pub_file.write(key.publickey().export_key()) # Сохраняем открытый ключ

# Функция для загрузки ключей из файлов
def load_keys(private_key_file, public_key_file):
    with open(private_key_file, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read()) # Загружаем закрытый ключ
    with open(public_key_file, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read()) # Загружаем открытый ключ
    return private_key, public_key

def main():
    # Пути к файлам ключей
    private_key_file = "client_private_key.pem"
    public_key_file = "client_public_key.pem"

    # Генерация или загрузка ключей
    generate_keys(private_key_file, public_key_file)
    client_private_key, client_public_key = load_keys(private_key_file, public_key_file)

    # Настраиваем клиентский сокет
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 8080)) # Подключаемся к серверу

    # Отправляем открытый ключ клиента серверу
    client_socket.send(base64.b64encode(client_public_key.export_key())) # Кодируем ключ в Base64 и отправляем

    # Получаем серверный публичный ключ
    server_public_key_data = base64.b64decode(client_socket.recv(4096)) # Декодируем данные из Base64
    server_public_key = RSA.import_key(server_public_key_data) # Импортируем открытый ключ сервера

    # Генерируем симметричный ключ AES
    aes_key = get_random_bytes(32) # Генерируем 256-битный ключ
    print("Симметричный ключ сгенерирован.")

    # Шифруем симметричный ключ серверным публичным ключом
    cipher_rsa = PKCS1_OAEP.new(server_public_key) # Создаем объект шифрования RSA
    encrypted_aes_key = cipher_rsa.encrypt(aes_key) # Шифруем ключ AES
    client_socket.send(encrypted_aes_key) # Отправляем зашифрованный AES ключ серверу

    # Отправляем зашифрованное сообщение серверу
    message = "Привет, сервер!".encode() # Сообщение для отправки
    iv = get_random_bytes(16) # Генерируем случайный IV
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv) # Создаем AES шифр
    encrypted_message = iv + cipher_aes.encrypt(pad(message, AES.block_size)) # Шифруем сообщение с добавлением IV
    client_socket.send(encrypted_message) # Отправляем зашифрованное сообщение

    # Получаем зашифрованный ответ от сервера
    encrypted_response = client_socket.recv(4096)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=encrypted_response[:16]) # Создаем AES шифр с полученным IV
    decrypted_response = unpad(cipher_aes.decrypt(encrypted_response[16:]), AES.block_size) # Расшифровываем ответ
    print(f"Ответ от сервера: {decrypted_response.decode()}")

    client_socket.close()

if __name__ == "__main__":
    main()