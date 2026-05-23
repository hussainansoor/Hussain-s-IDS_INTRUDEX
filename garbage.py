# import socket
# import threading
# import time
# from datetime import datetime

# class SimpleIDS:
#     def __init__(self):
#         self.suspicious_ips = set()
#         self.alerts = []
    
#     def detect_suspicious_activity(self):
#         print("🔍 IDS STARTED - Monitoring network...")
#         print("📊 Suspicious connections will be detected!")
#         print("-" * 50)
        
#         # Simulate network monitoring
#         suspicious_patterns = [
#             "scan", "nmap", "attack", "hack", "portscan",
#             "192.168.", "10.0.", "172.16."
#         ]
        
#         while True:
#             try:
#                 # Simulate packet capture
#                 fake_packet = f"192.168.1.{int(time.time())%255}:80"
                
#                 # Check for suspicious patterns
#                 if any(pattern in fake_packet for pattern in suspicious_patterns):
#                     self.alerts.append({
#                         'time': datetime.now().strftime("%H:%M:%S"),
#                         'ip': fake_packet.split(':')[0],
#                         'alert': 'PORT SCAN DETECTED!'
#                     })
#                     print(f"🚨 ALERT [{self.alerts[-1]['time']}]: {self.alerts[-1]['alert']}")
#                     print(f"   👾 Source: {self.alerts[-1]['ip']}")
                
#                 time.sleep(2)
                
#             except KeyboardInterrupt:
#                 print("\n✅ IDS STOPPED!")
#                 break

# # START IDS
# if __name__ == "__main__":
#     ids = SimpleIDS()
#     ids.detect_suspicious_activity()