# app.py - Исправленная версия с правильным контекстом приложения
import os
import sys
import threading
import time
import json
import random
from datetime import datetime, timedelta
import secrets
import io
import base64
from pathlib import Path

# Проверка зависимостей
try:
    from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
    from flask_socketio import SocketIO
    from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
    from flask_sqlalchemy import SQLAlchemy
    from werkzeug.security import generate_password_hash, check_password_hash
    import pyotp
    import qrcode
    print("✅ Все зависимости загружены успешно")
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    print("Установите зависимости: pip install -r requirements.txt")
    sys.exit(1)

# Определяем абсолютный путь к папке проекта
BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = BASE_DIR / 'data'

# Создаем папку data если её нет
DATA_DIR.mkdir(exist_ok=True, parents=True)

# Путь к базе данных с абсолютным путем
DB_PATH = DATA_DIR / 'security.db'
print(f"📁 Путь к базе данных: {DB_PATH}")

# Инициализация приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Инициализация расширений
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему для доступа к этой странице.'

# Глобальная переменная для хранения данных
monitoring_data = {
    'timestamp': datetime.now().isoformat(),
    'stats': {
        'packets_total': 0,
        'active_connections': 0,
        'alerts': 0,
        'bandwidth': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'http_requests': 0,
        'https_requests': 0
    },
    'alerts': [],
    'devices': [],
    'devices_online': 0,
    'threat_level': 'low',
    'threat_score': 0
}

# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def verify_mfa(self, token):
        if not self.mfa_secret:
            return True
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token, valid_window=2)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    user_agent = db.Column(db.Text)

class ThreatAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(20))
    type = db.Column(db.String(50))
    source_ip = db.Column(db.String(45))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)

class NetworkDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True)
    ip_address = db.Column(db.String(45))
    hostname = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Integer, default=0)
    is_trusted = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

def init_database():
    """Инициализация базы данных"""
    try:
        print("🗄️ Инициализация базы данных...")
        
        with app.app_context():
            db.create_all()
            print("✅ Таблицы базы данных созданы")
            
            # Создаем администратора если его нет
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    role='admin',
                    mfa_enabled=False
                )
                admin.set_password('admin123')
                db.session.add(admin)
                print("✅ Создан администратор: admin/admin123")
            
            # Создаем пользователя если его нет
            user = User.query.filter_by(username='user').first()
            if not user:
                user = User(
                    username='user',
                    role='user',
                    mfa_enabled=False
                )
                user.set_password('user123')
                db.session.add(user)
                print("✅ Создан пользователь: user/user123")
            
            # Создаем демо-оповещения
            if ThreatAlert.query.count() == 0:
                alerts = [
                    ThreatAlert(
                        severity='high',
                        type='port_scan',
                        source_ip='192.168.1.100',
                        description='Обнаружено сканирование портов',
                        timestamp=datetime.utcnow() - timedelta(hours=2)
                    ),
                    ThreatAlert(
                        severity='medium',
                        type='suspicious_connection',
                        source_ip='10.0.0.50',
                        description='Подозрительное соединение на порт 4444',
                        timestamp=datetime.utcnow() - timedelta(hours=1)
                    )
                ]
                db.session.add_all(alerts)
            
            # Создаем демо-устройства
            if NetworkDevice.query.count() == 0:
                devices = [
                    NetworkDevice(
                        mac_address='00:1A:2B:3C:4D:5E',
                        ip_address='192.168.1.10',
                        hostname='server-01',
                        device_type='server',
                        risk_score=10,
                        is_trusted=True
                    ),
                    NetworkDevice(
                        mac_address='00:1A:2B:3C:4D:5F',
                        ip_address='192.168.1.20',
                        hostname='workstation-01',
                        device_type='computer',
                        risk_score=30,
                        is_trusted=True
                    )
                ]
                db.session.add_all(devices)
            
            db.session.commit()
            print("✅ Демонстрационные данные созданы")
            
            print("\n" + "="*50)
            print("👤 Учетные данные для входа:")
            print("   Администратор: admin / admin123")
            print("   Пользователь:  user / user123")
            print("="*50 + "\n")
            
    except Exception as e:
        print(f"❌ Ошибка инициализации базы данных: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# Инициализация базы данных
init_database()

def generate_demo_data():
    """Генерация демо-данных без доступа к базе"""
    current_time = datetime.now()
    
    # Базовые статистики
    base_packets = 10000
    variation = random.randint(-2000, 2000)
    
    # Случайные устройства
    devices = []
    device_count = random.randint(5, 15)
    for i in range(device_count):
        devices.append({
            'id': i + 1,
            'mac': f'00:{random.randint(10,99):02d}:{random.randint(10,99):02d}:'
                   f'{random.randint(10,99):02d}:{random.randint(10,99):02d}:{random.randint(10,99):02d}',
            'ip': f'192.168.1.{random.randint(2, 254)}',
            'hostname': random.choice(['pc-', 'laptop-', 'phone-', 'tablet-', 'iot-']) + str(i+1),
            'device_type': random.choice(['computer', 'phone', 'tablet', 'server', 'router', 'iot']),
            'last_seen': (current_time - timedelta(minutes=random.randint(1, 60))).isoformat(),
            'risk_score': random.randint(0, 100),
            'trusted': random.choice([True, False])
        })
    
    # Случайные оповещения
    alerts = []
    alert_types = [
        ('port_scan', 'Сканирование портов'),
        ('brute_force', 'Попытка подбора пароля'),
        ('suspicious_connection', 'Подозрительное соединение'),
        ('malware_detected', 'Обнаружен вредоносный трафик')
    ]
    
    if random.random() < 0.3:
        alert_type, description = random.choice(alert_types)
        alerts.append({
            'id': random.randint(1000, 9999),
            'severity': random.choice(['low', 'medium', 'high']),
            'type': alert_type,
            'source_ip': f'192.168.1.{random.randint(100, 250)}',
            'description': f'{description}',
            'timestamp': current_time.isoformat(),
            'resolved': False
        })
    
    # Статистика
    stats = {
        'packets_total': base_packets + variation,
        'active_connections': random.randint(15, 85),
        'alerts': len(alerts),
        'bandwidth': random.randint(50, 500),
        'tcp_packets': random.randint(3000, 8000),
        'udp_packets': random.randint(1000, 4000),
        'http_requests': random.randint(500, 2000),
        'https_requests': random.randint(1000, 3000)
    }
    
    # Уровень угроз
    threat_score = random.randint(0, 100)
    if threat_score > 70:
        threat_level = 'high'
    elif threat_score > 40:
        threat_level = 'medium'
    else:
        threat_level = 'low'
    
    return {
        'timestamp': current_time.isoformat(),
        'stats': stats,
        'alerts': alerts,
        'devices': devices[:5],
        'devices_online': device_count,
        'threat_level': threat_level,
        'threat_score': threat_score
    }

# WebSocket обработчики
@socketio.on('connect')
def handle_connect():
    client_ip = request.remote_addr
    print(f'✅ Клиент подключен: {request.sid} (IP: {client_ip})')
    
    socketio.emit('connected', {
        'status': 'connected',
        'message': 'WebSocket соединение установлено',
        'timestamp': datetime.now().isoformat(),
        'client_ip': client_ip
    }, room=request.sid)
    
    # Отправляем текущие данные
    send_monitoring_data()

@socketio.on('disconnect')
def handle_disconnect():
    print(f'⚠️ Клиент отключен: {request.sid}')

@socketio.on('request_data')
def handle_request_data():
    print(f'📨 Получен запрос данных от клиента: {request.sid}')
    send_monitoring_data()

def send_monitoring_data():
    """Отправка данных мониторинга через WebSocket"""
    try:
        global monitoring_data
        monitoring_data = generate_demo_data()
        socketio.emit('monitoring_update', monitoring_data)
        print(f'📡 Отправлены данные мониторинга: {monitoring_data["timestamp"]}')
    except Exception as e:
        print(f'❌ Ошибка отправки данных: {e}')

# Маршруты
@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            
            # Логирование попытки входа
            attempt = LoginAttempt(
                username=username,
                ip_address=request.remote_addr,
                success=bool(user and user.check_password(password)),
                user_agent=request.user_agent.string
            )
            db.session.add(attempt)
            
            if user and user.check_password(password):
                attempt.success = True
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                # Проверяем MFA
                if user.mfa_enabled and user.mfa_secret:
                    session['pre_auth_user'] = user.id
                    session['remember'] = remember
                    flash('Требуется двухфакторная аутентификация', 'info')
                    return redirect(url_for('mfa_verify'))
                
                # Иначе просто логиним
                login_user(user, remember=remember)
                flash(f'Успешный вход, {user.username}!', 'success')
                return redirect(url_for('index'))
            else:
                db.session.commit()
                flash('Неверное имя пользователя или пароль', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """Настройка двухфакторной аутентификации"""
    
    with app.app_context():
        if request.method == 'POST':
            action = request.form.get('action', '')
            
            if action == 'setup':
                # Генерация нового секрета
                secret = pyotp.random_base32()
                current_user.mfa_secret = secret
                current_user.mfa_enabled = False
                db.session.commit()
                
                # Генерация QR-кода
                totp = pyotp.TOTP(secret)
                uri = totp.provisioning_uri(
                    name=current_user.username,
                    issuer_name="Система безопасности сети"
                )
                
                img = qrcode.make(uri)
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                buf.seek(0)
                img_str = base64.b64encode(buf.getvalue()).decode()
                
                # Сохраняем в сессии
                session['mfa_temp_secret'] = secret
                session['mfa_setup_time'] = time.time()
                
                return render_template('mfa_setup.html',
                                    qr_code=img_str,
                                    secret=secret,
                                    step='verify')
            
            elif action == 'verify':
                # Проверка введенного кода
                token = request.form.get('token', '').strip()
                temp_secret = session.get('mfa_temp_secret')
                
                if not temp_secret:
                    flash('Сессия истекла. Начните настройку заново.', 'danger')
                    return redirect(url_for('mfa_setup'))
                
                if not token or len(token) != 6 or not token.isdigit():
                    flash('Введите 6-значный код из приложения', 'danger')
                    return render_template('mfa_setup.html',
                                        secret=temp_secret,
                                        step='verify')
                
                # Проверяем код
                totp = pyotp.TOTP(temp_secret)
                
                # Для отладки
                expected_token = totp.now()
                print(f"[MFA] Введенный токен: {token}")
                print(f"[MFA] Ожидаемый токен: {expected_token}")
                print(f"[MFA] Секрет: {temp_secret}")
                
                if totp.verify(token, valid_window=2):
                    # Успешная проверка
                    current_user.mfa_secret = temp_secret
                    current_user.mfa_enabled = True
                    db.session.commit()
                    
                    # Очищаем временные данные
                    session.pop('mfa_temp_secret', None)
                    session.pop('mfa_setup_time', None)
                    
                    # Генерация резервных кодов
                    backup_codes = []
                    for i in range(8):
                        code = f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
                        backup_codes.append(code)
                    
                    session['backup_codes'] = backup_codes
                    
                    flash('✅ MFA успешно настроена!', 'success')
                    return redirect(url_for('mfa_backup'))
                else:
                    flash('❌ Неверный код. Проверьте синхронизацию времени.', 'danger')
                    return render_template('mfa_setup.html',
                                        secret=temp_secret,
                                        step='verify')
    
    # GET запрос - начало настройки
    return render_template('mfa_setup.html', step='setup')

@app.route('/mfa/backup')
@login_required
def mfa_backup():
    """Показ резервных кодов"""
    backup_codes = session.get('backup_codes', [])
    if not backup_codes:
        flash('Сначала настройте MFA', 'warning')
        return redirect(url_for('mfa_setup'))
    
    return render_template('mfa_backup.html', 
                         backup_codes=backup_codes,
                         current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    """Верификация MFA при входе"""
    if 'pre_auth_user' not in session:
        return redirect(url_for('login'))
    
    with app.app_context():
        user = User.query.get(session['pre_auth_user'])
        if not user:
            session.pop('pre_auth_user', None)
            session.pop('remember', None)
            flash('Ошибка пользователя', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            token = request.form.get('token', '').strip()
            remember = session.get('remember', False)
            
            if not token or len(token) != 6 or not token.isdigit():
                flash('Введите 6-значный код из приложения', 'danger')
                return render_template('mfa_verify.html', username=user.username)
            
            if user.verify_mfa(token):
                login_user(user, remember=remember)
                session.pop('pre_auth_user', None)
                session.pop('remember', None)
                flash('Двухфакторная аутентификация успешна!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Неверный код MFA. Попробуйте снова.', 'danger')
    
    return render_template('mfa_verify.html', username=user.username)

# API маршруты
@app.route('/api/traffic')
@login_required
def get_traffic_data():
    """API для получения статистики трафика"""
    return jsonify(monitoring_data['stats'])

@app.route('/api/alerts')
@login_required
def get_alerts():
    """API для получения оповещений"""
    with app.app_context():
        alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).limit(20).all()
        return jsonify([{
            'id': a.id,
            'severity': a.severity,
            'type': a.type,
            'source_ip': a.source_ip,
            'description': a.description,
            'timestamp': a.timestamp.isoformat() if a.timestamp else None,
            'resolved': a.resolved
        } for a in alerts])

@app.route('/api/devices')
@login_required
def get_devices():
    """API для получения списка устройств"""
    with app.app_context():
        devices = NetworkDevice.query.order_by(NetworkDevice.last_seen.desc()).limit(20).all()
        return jsonify([{
            'id': d.id,
            'mac': d.mac_address,
            'ip': d.ip_address,
            'hostname': d.hostname,
            'device_type': d.device_type,
            'first_seen': d.first_seen.isoformat() if d.first_seen else None,
            'last_seen': d.last_seen.isoformat() if d.last_seen else None,
            'risk_score': d.risk_score,
            'trusted': d.is_trusted
        } for d in devices])

@app.route('/api/system/health')
@login_required
def system_health():
    """API для проверки состояния системы"""
    return jsonify({
        'status': 'healthy',
        'database': 'connected',
        'websocket': 'active',
        'timestamp': datetime.now().isoformat(),
        'uptime': time.time() - app_start_time
    })

def background_monitoring():
    """Фоновый мониторинг сети"""
    print("🚀 Запуск фонового мониторинга...")
    time.sleep(2)
    
    while True:
        try:
            # Используем app_context для работы с Flask
            with app.app_context():
                send_monitoring_data()
            time.sleep(5)
        except Exception as e:
            print(f"❌ Ошибка мониторинга: {e}")
            time.sleep(10)

if __name__ == '__main__':
    # Запоминаем время старта
    app_start_time = time.time()
    
    # Запуск фонового потока мониторинга
    monitor_thread = threading.Thread(target=background_monitoring, daemon=True)
    monitor_thread.start()
    
    print("\n" + "="*50)
    print("🚀 Система безопасности запущена!")
    print(f"📁 База данных: {DB_PATH}")
    print("🔗 Доступна по адресу: http://localhost:5000")
    print("📡 WebSocket: ws://localhost:5000/socket.io/")
    print("\n👤 Учетные данные:")
    print("   Администратор: admin / admin123")
    print("   Пользователь:  user / user123")
    print("\n⚠️  Рекомендации:")
    print("   1. Смените пароли после первого входа")
    print("   2. Настройте MFA для администратора")
    print("="*50 + "\n")
    
    # Запуск приложения
    try:
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=5000, 
                    debug=True,
                    allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n\n👋 Завершение работы системы...")
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")