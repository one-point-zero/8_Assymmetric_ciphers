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
    private_key_file = "server_private_key.pem"
    public_key_file = "server_public_key.pem"

    # Генерация или загрузка ключей
    generate_keys(private_key_file, public_key_file)
    server_private_key, server_public_key = load_keys(private_key_file, public_key_file)

    # Настраиваем серверный сокет
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 8080)) # Привязываем к локальному адресу и порту
    server_socket.listen(1) # Ожидаем одно подключение

    print("Сервер запущен. Ожидание подключения клиента...")

    client_socket, address = server_socket.accept() # Принимаем подключение клиента
    print(f"Подключение клиента: {address}")

    # Получаем открытый ключ клиента
    client_public_key_data = base64.b64decode(client_socket.recv(4096)) # Декодируем данные из Base64
    client_public_key = RSA.import_key(client_public_key_data) # Импортируем открытый ключ клиента

    # Отправляем серверный публичный ключ
    client_socket.send(base64.b64encode(server_public_key.export_key())) # Кодируем ключ в Base64 и отправляем

    # Получаем зашифрованный симметричный ключ от клиента
    encrypted_aes_key = client_socket.recv(4096)
    cipher_rsa = PKCS1_OAEP.new(server_private_key) # Создаем объект для расшифровки с использованием закрытого ключа
    aes_key = cipher_rsa.decrypt(encrypted_aes_key) # Расшифровываем симметричный ключ

    print("Симметричный ключ успешно получен.")

    # Принимаем зашифрованное сообщение
    encrypted_message = client_socket.recv(4096)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=encrypted_message[:16])  # Инициализируем AES с IV (первые 16 байт)
    decrypted_message = unpad(cipher_aes.decrypt(encrypted_message[16:]), AES.block_size) # Расшифровываем и удаляем паддинг
    print(f"Сообщение от клиента: {decrypted_message.decode()}")

    # Отправляем зашифрованный ответ
    response = "Сообщение получено!".encode() # Формируем сообщение
    iv = get_random_bytes(16) # Генерируем случайный IV
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv) # Создаем AES шифр
    encrypted_response = iv + cipher_aes.encrypt(pad(response, AES.block_size)) # Шифруем сообщение с добавлением IV
    client_socket.send(encrypted_response) # Отправляем зашифрованный ответ

    # Закрываем соединение
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()