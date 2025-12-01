# debug_mfa.py
#!/usr/bin/env python3
import pyotp
import base64
import qrcode
import io
from datetime import datetime

print("🔍 Отладка MFA")
print("="*50)

# Генерация тестового секрета
secret = pyotp.random_base32()
print(f"Секрет: {secret}")

# Создание TOTP объекта
totp = pyotp.TOTP(secret)

# Получение текущего токена
current_token = totp.now()
print(f"Текущий токен: {current_token}")
print(f"Время: {datetime.now().strftime('%H:%M:%S')}")

# Генерация URI для QR-кода
uri = totp.provisioning_uri(
    name="test@example.com",
    issuer_name="Security System"
)
print(f"URI: {uri}")

# Проверка токена
test_token = input("\nВведите токен из Google Authenticator: ")
if totp.verify(test_token):
    print("✅ Токен верный!")
else:
    print("❌ Токен неверный!")
    print(f"Ожидался: {current_token}")