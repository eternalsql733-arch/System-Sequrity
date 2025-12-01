# advanced_threat_detection.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
import pandas as pd
import joblib
from datetime import datetime, timedelta

class AdvancedThreatDetection:
    def __init__(self):
        # Модели машинного обучения
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.nn_model = self.build_nn_model()
        self.threat_signatures = self.load_threat_signatures()
        self.anomaly_history = []
        
        # Статистика сети
        self.network_baseline = {}
        self.behavior_profiles = {}
        
    def build_nn_model(self):
        """Нейросеть для обнаружения аномалий"""
        model = keras.Sequential([
            keras.layers.Dense(64, activation='relu', input_shape=(20,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def load_threat_signatures(self):
        """Загрузка сигнатур угроз"""
        signatures = {
            'c2_communication': {
                'patterns': [
                    '.*\.onion',
                    '.*\.xyz',
                    '.*\.top',
                    'beacon.*interval',
                    'heartbeat.*jitter'
                ],
                'ports': [4444, 8080, 8443, 9001]
            },
            'data_exfiltration': {
                'indicators': [
                    'large_upload_volume',
                    'unusual_protocol_mix',
                    'encrypted_traffic_to_external',
                    'base64_in_payload'
                ]
            },
            'lateral_movement': {
                'patterns': [
                    'smb.*\\.\\.\\',
                    'wmi.*remote',
                    'ps_exec.*-computername',
                    'winrm.*invoke'
                ]
            },
            'ransomware': {
                'indicators': [
                    'file_encryption_pattern',
                    'ransom_note_in_traffic',
                    'tor_connection_attempt',
                    'mass_file_rename'
                ]
            }
        }
        return signatures
    
    def detect_threats(self, traffic_data):
        """Обнаружение угроз"""
        threats = []
        
        # 1. Сигнатурный анализ
        threats.extend(self.signature_analysis(traffic_data))
        
        # 2. Анализ аномалий
        threats.extend(self.anomaly_detection(traffic_data))
        
        # 3. Поведенческий анализ
        threats.extend(self.behavioral_analysis(traffic_data))
        
        # 4. Анализ цепочек атак (Cyber Kill Chain)
        threats.extend(self.kill_chain_analysis(traffic_data))
        
        return threats
    
    def signature_analysis(self, traffic_data):
        """Анализ по сигнатурам"""
        detected = []
        
        for packet in traffic_data:
            # Проверка C2 сигнатур
            if self.check_c2_patterns(packet):
                detected.append({
                    'type': 'c2_communication',
                    'severity': 'critical',
                    'source': packet.get('src_ip'),
                    'description': 'Обнаружена командно-административная связь',
                    'confidence': 0.85
                })
            
            # Проверка эксфильтрации данных
            if self.check_data_exfiltration(packet):
                detected.append({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'source': packet.get('src_ip'),
                    'description': 'Возможная эксфильтрация данных',
                    'confidence': 0.75
                })
        
        return detected
    
    def check_c2_patterns(self, packet):
        """Проверка паттернов C2"""
        payload = packet.get('payload', '').lower()
        
        # Проверка доменов ботнетов
        suspicious_domains = [
            'cryptolocker', 'zeus', 'darkness',
            'empire', 'cobalt', 'metasploit'
        ]
        
        for domain in suspicious_domains:
            if domain in payload:
                return True
        
        # Проверка портов C2
        if packet.get('dst_port') in self.threat_signatures['c2_communication']['ports']:
            return True
        
        return False
    
    def anomaly_detection(self, traffic_data):
        """Обнаружение аномалий с помощью ML"""
        features = self.extract_features(traffic_data)
        
        if len(features) > 0:
            # Нормализация признаков
            features_scaled = self.scaler.transform([features])
            
            # Предсказание аномалий
            anomaly_score = self.isolation_forest.score_samples(features_scaled)[0]
            
            if anomaly_score < -0.5:  # Пороговое значение
                return [{
                    'type': 'network_anomaly',
                    'severity': 'high',
                    'score': float(anomaly_score),
                    'description': 'Обнаружена аномальная сетевая активность',
                    'confidence': 0.8
                }]
        
        return []
    
    def extract_features(self, traffic_data):
        """Извлечение признаков для ML"""
        if not traffic_data:
            return []
        
        features = []
        
        # Статистика трафика
        packet_sizes = [p.get('size', 0) for p in traffic_data]
        inter_arrival_times = []
        
        for i in range(1, len(traffic_data)):
            time_diff = traffic_data[i]['timestamp'] - traffic_data[i-1]['timestamp']
            inter_arrival_times.append(time_diff)
        
        features.extend([
            np.mean(packet_sizes),
            np.std(packet_sizes),
            np.max(packet_sizes),
            np.min(packet_sizes),
            np.mean(inter_arrival_times) if inter_arrival_times else 0,
            np.std(inter_arrival_times) if inter_arrival_times else 0,
            len(traffic_data),
            len(set(p.get('src_ip') for p in traffic_data)),
            len(set(p.get('dst_ip') for p in traffic_data)),
            sum(1 for p in traffic_data if p.get('protocol') == 6),  # TCP
            sum(1 for p in traffic_data if p.get('protocol') == 17),  # UDP
            sum(1 for p in traffic_data if p.get('dst_port') < 1024),
            sum(1 for p in traffic_data if 1024 <= p.get('dst_port', 0) < 49152),
            sum(1 for p in traffic_data if p.get('dst_port') >= 49152)
        ])
        
        return features[:20]  # Ограничение до 20 признаков
    
    def kill_chain_analysis(self, traffic_data):
        """Анализ по модели Cyber Kill Chain"""
        kill_chain_stages = {
            'reconnaissance': self.detect_reconnaissance,
            'weaponization': self.detect_weaponization,
            'delivery': self.detect_delivery,
            'exploitation': self.detect_exploitation,
            'installation': self.detect_installation,
            'command_control': self.detect_command_control,
            'actions_objectives': self.detect_actions_objectives
        }
        
        threats = []
        for stage, detector in kill_chain_stages.items():
            if result := detector(traffic_data):
                threats.append({
                    'type': f'kill_chain_{stage}',
                    'severity': 'medium',
                    'stage': stage,
                    'description': result,
                    'confidence': 0.7
                })
        
        return threats
    
    def detect_reconnaissance(self, traffic_data):
        """Обнаружение разведки"""
        scan_threshold = 100  # Порог для сканирования
        
        src_counts = {}
        for packet in traffic_data:
            src_ip = packet.get('src_ip')
            src_counts[src_ip] = src_counts.get(src_ip, 0) + 1
        
        for src_ip, count in src_counts.items():
            if count > scan_threshold:
                return f"Обнаружено сканирование сети с {src_ip}"
        
        return None