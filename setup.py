# setup.py - установка и настройка
#!/usr/bin/env python3
import os
import sys
import subprocess

def check_python():
    """Проверка версии Python"""
    if sys.version_info < (3, 8):
        print("❌ Требуется Python 3.8 или выше")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

def install_dependencies():
    """Установка зависимостей"""
    print("\n📦 Установка зависимостей...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Зависимости установлены")
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка установки зависимостей: {e}")
        sys.exit(1)

def create_directories():
    """Создание структуры директорий"""
    directories = ['static', 'templates', 'data', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Создана директория: {directory}")

def check_templates():
    """Проверка HTML шаблонов"""
    required_templates = ['login.html', 'dashboard.html', 'mfa_setup.html', 'mfa_verify.html']
    
    for template in required_templates:
        if not os.path.exists(f'templates/{template}'):
            print(f"⚠️ Отсутствует шаблон: {template}")
            
            # Создаем простой шаблон если отсутствует
            if template == 'login.html':
                create_simple_login_template()
            elif template == 'dashboard.html':
                create_simple_dashboard_template()
            print(f"✅ Создан базовый шаблон: {template}")

def create_simple_dashboard_template():
    """Создание простого dashboard.html"""
    html = '''<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard</title>
    <script src="https://cdn.socket.io/4.0.1/socket.io.min.js"></script>
    <style>
        body { font-family: Arial; margin: 20px; }
        .card { border: 1px solid #ddd; padding: 15px; margin: 10px; border-radius: 5px; }
        .connected { color: green; }
        .disconnected { color: red; }
    </style>
</head>
<body>
    <h1>Security Dashboard</h1>
    <div id="status">Статус: <span class="disconnected">Ожидание данных...</span></div>
    
    <div class="card">
        <h3>📡 Активность сети</h3>
        <div id="packets">Пакеты: 0</div>
        <div id="connections">Соединения: 0</div>
    </div>
    
    <div class="card">
        <h3>⚠️ Инциденты</h3>
        <div id="alerts">Активных инцидентов: 0</div>
    </div>
    
    <script>
        const socket = io();
        
        socket.on('connect', () => {
            document.querySelector('#status').innerHTML = 'Статус: <span class="connected">Подключено</span>';
            console.log('✅ WebSocket подключен');
        });
        
        socket.on('monitoring_update', (data) => {
            console.log('📊 Получены данные:', data);
            document.getElementById('packets').textContent = `Пакеты: ${data.stats.packets_total}`;
            document.getElementById('connections').textContent = `Соединения: ${data.stats.active_connections}`;
            document.getElementById('alerts').textContent = `Активных инцидентов: ${data.stats.alerts}`;
        });
        
        socket.on('disconnect', () => {
            document.querySelector('#status').innerHTML = 'Статус: <span class="disconnected">Отключено</span>';
        });
    </script>
</body>
</html>'''
    
    with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
        f.write(html)

def create_simple_login_template():
    """Создание простого login.html"""
    html = '''<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-box { padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        input { display: block; margin: 10px 0; padding: 8px; width: 200px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Вход в систему</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Имя пользователя" required>
            <input type="password" name="password" placeholder="Пароль" required>
            <button type="submit">Войти</button>
        </form>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div style="color: red; margin-top: 10px;">
              {% for message in messages %}
                {{ message }}
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}
    </div>
</body>
</html>'''
    
    with open('templates/login.html', 'w', encoding='utf-8') as f:
        f.write(html)

if __name__ == '__main__':
    print("🚀 Настройка системы безопасности...")
    check_python()
    install_dependencies()
    create_directories()
    check_templates()
    print("\n✅ Система готова к запуску!")
    print("\nЗапустите команду: python app.py")
    print("Или: python run.py")