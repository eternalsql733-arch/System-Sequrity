# auth_system.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import datetime
import ipaddress

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    role = db.Column(db.String(20), default='user')
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    success = db.Column(db.Boolean)
    user_agent = db.Column(db.Text)
    location = db.Column(db.String(100))

class AuthSystem:
    def __init__(self):
        self.max_attempts = 5
        self.lockout_duration = 15  # минут
        
    def authenticate(self, username, password):
        # Проверка блокировки IP
        if self.is_ip_blocked(request.remote_addr):
            return None
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Сброс счетчика попыток
            user.login_attempts = 0
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            return user
        
        # Увеличение счетчика неудачных попыток
        if user:
            user.login_attempts += 1
            if user.login_attempts >= self.max_attempts:
                user.locked_until = datetime.datetime.utcnow() + \
                    datetime.timedelta(minutes=self.lockout_duration)
            db.session.commit()
        
        return None
    
    def verify_mfa(self, user, token):
        if not user.mfa_secret:
            return True
        
        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(token, valid_window=1)
    
    def is_ip_blocked(self, ip_address):
        # Проверка блокировки по IP
        recent_attempts = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.timestamp > datetime.datetime.utcnow() - datetime.timedelta(hours=1),
            LoginAttempt.success == False
        ).count()
        
        return recent_attempts >= 10
    
    def log_login_attempt(self, username, success, ip_address):
        attempt = LoginAttempt(
            username=username,
            ip_address=ip_address,
            success=success,
            user_agent=request.user_agent.string,
            location=self.geolocate_ip(ip_address)
        )
        db.session.add(attempt)
        db.session.commit()
    
    def geolocate_ip(self, ip_address):
        try:
            import geoip2.database
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.city(ip_address)
            return f"{response.city.name}, {response.country.name}"
        except:
            return "Unknown"