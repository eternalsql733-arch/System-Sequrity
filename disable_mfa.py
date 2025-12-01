# disable_mfa.py
#!/usr/bin/env python3
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BASE_DIR))

print("🛠️ Отключение MFA для всех пользователей...")

# Импортируем после добавления пути
from app import app, db, User

with app.app_context():
    # Отключаем MFA для всех пользователей
    users = User.query.all()
    for user in users:
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_setup_complete = False
        print(f"✅ MFA отключена для пользователя: {user.username}")
    
    db.session.commit()
    print("\n✅ MFA полностью отключена для всех пользователей!")
    print("Теперь вы можете войти без MFA:")
    print("Логин: admin")
    print("Пароль: admin123")