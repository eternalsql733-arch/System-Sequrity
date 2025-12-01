# behavioral_analytics.py
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib

class BehavioralAnalytics:
    def __init__(self):
        # Базовые профили поведения
        self.behavior_profiles = defaultdict(lambda: {
            'normal_traffic': deque(maxlen=1000),
            'access_patterns': defaultdict(int),
            'temporal_patterns': defaultdict(lambda: defaultdict(int)),
            'anomaly_score': 0
        })
        
        # Периоды обучения
        self.learning_periods = {
            'daily': timedelta(days=1),
            'weekly': timedelta(weeks=1),
            'monthly': timedelta(days=30)
        }
        
        # Статистика
        self.stats = {
            'total_anomalies': 0,
            'deviation_scores': {},
            'correlation_matrix': {}
        }
    
    def analyze_behavior(self, traffic_data):
        """Анализ поведения устройств"""
        anomalies = []
        
        for packet in traffic_data:
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            # Анализ источника
            src_anomaly = self.analyze_device_behavior(src_ip, packet, 'source')
            if src_anomaly:
                anomalies.append(src_anomaly)
            
            # Анализ назначения
            dst_anomaly = self.analyze_device_behavior(dst_ip, packet, 'destination')
            if dst_anomaly:
                anomalies.append(dst_anomaly)
            
            # Анализ взаимодействия
            interaction_anomaly = self.analyze_interaction(src_ip, dst_ip, packet)
            if interaction_anomaly:
                anomalies.append(interaction_anomaly)
        
        return anomalies
    
    def analyze_device_behavior(self, device_ip, packet, role):
        """Анализ поведения отдельного устройства"""
        profile = self.behavior_profiles[device_ip]
        
        # Обновление профиля
        profile['normal_traffic'].append({
            'size': packet.get('size', 0),
            'time': packet.get('timestamp'),
            'protocol': packet.get('protocol'),
            'port': packet.get('dst_port')
        })
        
        # Вычисление отклонений
        deviations = self.calculate_deviations(profile, packet, role)
        
        if deviations['total_score'] > 0.7:  # Порог аномалии
            self.stats['total_anomalies'] += 1
            
            return {
                'type': 'behavioral_anomaly',
                'device': device_ip,
                'role': role,
                'score': deviations['total_score'],
                'deviations': deviations['details'],
                'timestamp': datetime.now().isoformat()
            }
        
        return None
    
    def calculate_deviations(self, profile, packet, role):
        """Вычисление отклонений от нормального поведения"""
        deviations = {
            'size': 0,
            'frequency': 0,
            'protocol': 0,
            'time': 0,
            'total_score': 0
        }
        
        # Отклонение по размеру пакетов
        if profile['normal_traffic']:
            sizes = [p['size'] for p in profile['normal_traffic']]
            avg_size = np.mean(sizes)
            std_size = np.std(sizes)
            
            current_size = packet.get('size', 0)
            if std_size > 0:
                size_zscore = abs(current_size - avg_size) / std_size
                deviations['size'] = min(size_zscore / 5, 1)  # Нормализация
        
        # Отклонение по протоколам
        protocol_counts = defaultdict(int)
        for p in profile['normal_traffic']:
            protocol_counts[p['protocol']] += 1
        
        current_protocol = packet.get('protocol')
        total_packets = len(profile['normal_traffic'])
        
        if total_packets > 0:
            expected_prob = protocol_counts.get(current_protocol, 0) / total_packets
            deviations['protocol'] = 1 - expected_prob
        
        # Временное отклонение
        current_hour = datetime.now().hour
        hour_counts = sum(1 for p in profile['normal_traffic'] 
                         if datetime.fromtimestamp(p['time']).hour == current_hour)
        
        if total_packets > 0:
            hour_prob = hour_counts / total_packets
            deviations['time'] = 1 - hour_prob
        
        # Общий счет
        weights = {'size': 0.3, 'frequency': 0.2, 'protocol': 0.3, 'time': 0.2}
        deviations['total_score'] = sum(
            deviations[key] * weights[key] 
            for key in weights.keys()
        )
        
        return deviations
    
    def analyze_interaction(self, src_ip, dst_ip, packet):
        """Анализ взаимодействия между устройствами"""
        interaction_key = f"{src_ip}-{dst_ip}"
        
        # Проверка новых связей
        if not self.is_established_connection(interaction_key):
            # Анализ подозрительных новых связей
            suspicious_patterns = self.check_suspicious_interaction(
                src_ip, dst_ip, packet
            )
            
            if suspicious_patterns:
                return {
                    'type': 'suspicious_connection',
                    'source': src_ip,
                    'destination': dst_ip,
                    'patterns': suspicious_patterns,
                    'severity': 'medium'
                }
        
        return None
    
    def is_established_connection(self, interaction_key):
        """Проверка установленного соединения"""
        # Здесь должна быть логика проверки истории соединений
        return interaction_key in self.behavior_profiles
    
    def check_suspicious_interaction(self, src_ip, dst_ip, packet):
        """Проверка подозрительных взаимодействий"""
        suspicious_patterns = []
        
        # Связь с необычным портом
        if packet.get('dst_port') in [22, 3389, 5985, 5986]:  # SSH, RDP, WinRM
            if not self.is_expected_port(src_ip, packet.get('dst_port')):
                suspicious_patterns.append('unexpected_admin_port')
        
        # Большой объем данных от нового источника
        if packet.get('size', 0) > 1000000:  # 1MB
            suspicious_patterns.append('large_data_transfer_new_source')
        
        # Ночная активность
        current_hour = datetime.now().hour
        if 0 <= current_hour <= 5:
            suspicious_patterns.append('nocturnal_activity')
        
        return suspicious_patterns
    
    def get_anomalies(self):
        """Получение обнаруженных аномалий"""
        return {
            'total_anomalies': self.stats['total_anomalies'],
            'top_anomalous_devices': self.get_top_anomalous_devices(10),
            'temporal_patterns': self.get_temporal_patterns()
        }
    
    def get_top_anomalous_devices(self, limit=10):
        """Получение самых аномальных устройств"""
        devices_scores = []
        
        for device, profile in self.behavior_profiles.items():
            if len(profile['normal_traffic']) > 100:  # Минимум 100 пакетов
                devices_scores.append({
                    'device': device,
                    'anomaly_score': profile['anomaly_score'],
                    'packet_count': len(profile['normal_traffic'])
                })
        
        return sorted(devices_scores, 
                     key=lambda x: x['anomaly_score'], 
                     reverse=True)[:limit]