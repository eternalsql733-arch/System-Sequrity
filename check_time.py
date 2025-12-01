# check_time.py
#!/usr/bin/env python3
from datetime import datetime
import time
import ntplib

print("🕐 Проверка синхронизации времени")
print("="*50)

# Локальное время
local_time = datetime.now()
print(f"Локальное время: {local_time}")

# Попытка получить время NTP
try:
    client = ntplib.NTPClient()
    response = client.request('pool.ntp.org')
    ntp_time = datetime.fromtimestamp(response.tx_time)
    print(f"NTP время: {ntp_time}")
    
    # Разница во времени
    diff = abs((local_time - ntp_time).total_seconds())
    print(f"Разница: {diff:.2f} секунд")
    
    if diff > 30:
        print("⚠️ Большая разница во времени! Это может быть причиной ошибки MFA.")
    else:
        print("✅ Время синхронизировано")
except:
    print("⚠️ Не удалось проверить NTP время")

print("\n🔧 Решения:")
print("1. Проверьте время на телефоне (должно быть выставлено автоматически)")
print("2. Проверьте время на сервере: sudo ntpdate pool.ntp.org")
print("3. Используйте команду 'date' для проверки времени")