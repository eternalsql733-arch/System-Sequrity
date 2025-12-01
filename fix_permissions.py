# fix_permissions.py
#!/usr/bin/env python3
import os
import sys
import stat
from pathlib import Path

def fix_permissions():
    """Исправление разрешений для файлов и папок"""
    base_dir = Path(__file__).parent.absolute()
    
    # Папки для создания
    dirs = ['data', 'static', 'templates', 'logs']
    
    # Файлы для проверки
    files = ['requirements.txt', 'app.py']
    
    print("🔧 Исправление разрешений...")
    
    # Создаем папки с правильными разрешениями
    for dir_name in dirs:
        dir_path = base_dir / dir_name
        try:
            dir_path.mkdir(exist_ok=True)
            # Устанавливаем разрешения 755 для папок
            os.chmod(dir_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            print(f"✅ Папка создана/проверена: {dir_name}")
        except Exception as e:
            print(f"❌ Ошибка создания папки {dir_name}: {e}")
    
    # Проверяем файлы
    for file_name in files:
        file_path = base_dir / file_name
        if file_path.exists():
            try:
                # Устанавливаем разрешения 644 для файлов
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                print(f"✅ Файл проверен: {file_name}")
            except Exception as e:
                print(f"⚠️ Ошибка проверки файла {file_name}: {e}")
        else:
            print(f"⚠️ Файл не найден: {file_name}")
    
    # Специальная проверка для базы данных
    db_path = base_dir / 'data' / 'security.db'
    if db_path.exists():
        try:
            # База данных должна быть доступна для записи
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
            print(f"✅ Разрешения для базы данных установлены")
        except Exception as e:
            print(f"⚠️ Ошибка установки разрешений для БД: {e}")
    else:
        print(f"ℹ️ База данных не найдена, будет создана при первом запуске")
    
    print("\n✅ Проверка разрешений завершена")

if __name__ == '__main__':
    fix_permissions()