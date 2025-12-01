#!/usr/bin/env python3
# test_fix.py - Тестирование исправлений

import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BASE_DIR))

print("🧪 Тестирование исправлений...")

try:
    from app import app, db
    
    # Тест 1: Проверка контекста приложения
    with app.app_context():
        db.create_all()
        print("✅ Контекст приложения работает")
    
    # Тест 2: Проверка импортов
    import pyotp
    import qrcode
    print("✅ Все зависимости импортируются")
    
    # Тест 3: Генерация тестовых данных
    from app import generate_demo_data
    data = generate_demo_data()
    print(f"✅ Данные сгенерированы: {len(data['devices'])} устройств")
    
    print("\n" + "="*50)
    print("✅ Все тесты пройдены успешно!")
    print("Система готова к запуску.")
    print("="*50)
    
except Exception as e:
    print(f"❌ Ошибка тестирования: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)