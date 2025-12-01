# reset_mfa.py
#!/usr/bin/env python3
import sys
from pathlib import Path

# Добавляем текущую директорию в путь
BASE_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BASE_DIR))

from app import app, db, User

def reset_admin_mfa():
    """Сброс MFA для администратора"""
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print(f"Текущие настройки администратора:")
            print(f"  Имя пользователя: {admin.username}")
            print(f"  MFA включена: {admin.mfa_enabled}")
            print(f"  MFA настроена: {admin.mfa_setup_complete}")
            print(f"  Есть секрет: {'Да' if admin.mfa_secret else 'Нет'}")
            
            confirm = input("\nСбросить MFA для администратора? (y/N): ")
            if confirm.lower() == 'y':
                admin.mfa_enabled = False
                admin.mfa_secret = None
                admin.mfa_setup_complete = False
                db.session.commit()
                print("✅ MFA сброшена для администратора")
                print("Теперь вы можете войти без MFA и настроить её заново.")
            else:
                print("❌ Отмена сброса")
        else:
            print("❌ Администратор не найден")

if __name__ == '__main__':
    print("🛠️  Утилита сброса MFA")
    print("="*50)
    reset_admin_mfa()