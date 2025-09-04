import subprocess
import sys

print("Nexus-Scanner Final Test")
print("=======================")

# Nmap'in çalışıp çalışmadığını test et
try:
    result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ Nmap başarıyla kuruldu ve çalışıyor!")
        print(f"Nmap versiyonu: {result.stdout.split()[2]}")
    else:
        print("✗ Nmap kurulu ancak çalışmıyor")
except FileNotFoundError:
    print("✗ Nmap bulunamadı")

# Python modüllerini test et
try:
    import nmap
    print("✓ python-nmap modülü yüklü")
except ImportError:
    print("✗ python-nmap modülü yüklü değil")

try:
    import requests
    print("✓ requests modülü yüklü")
except ImportError:
    print("✗ requests modülü yüklü değil")

# Basit bir localhost tarama testi
print("\nBasit localhost tarama testi:")
print("=============================")

try:
    # Doğrudan subprocess ile nmap çalıştır
    result = subprocess.run(['nmap', '-p', '80,443,22', '127.0.0.1'], 
                          capture_output=True, text=True, timeout=30)
    
    if result.returncode == 0:
        print("✓ Localhost tarama başarılı!")
        print("\nTarama sonuçları:")
        print(result.stdout)
    else:
        print("✗ Tarama başarısız")
        print(f"Hata: {result.stderr}")
        
except subprocess.TimeoutExpired:
    print("✗ Tarama zaman aşımına uğradı")
except Exception as e:
    print(f"✗ Tarama hatası: {str(e)}")

print("\nTest tamamlandı!")