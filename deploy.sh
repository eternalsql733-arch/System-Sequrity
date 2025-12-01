#!/bin/bash
# deploy.sh

# Установка зависимостей
pip install -r requirements.txt --user

# Скачивание баз данных GeoIP
wget -O GeoLite2-City.mmdb.gz https://git.io/GeoLite2-City.mmdb.gz
gunzip GeoLite2-City.mmdb.gz

# Создание директорий
mkdir -p logs backups threat_feeds

# Инициализация базы данных
python -c "from app import db, app; with app.app_context(): db.create_all()"

# Запуск Redis для кэширования
sudo systemctl start redis

# Настройка сервиса
sudo cp security-system.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable security-system
sudo systemctl start security-system

# Настройка SSL (самоподписанный сертификат для тестов)
openssl req -x509 -newkey rsa:4096 -nodes \
    -out cert.pem -keyout key.pem \
    -days 365 -subj "/CN=security-system.local"