import nmap
import sys

# Çıktıyı dosyaya yönlendir
output_file = open('scan_results.txt', 'w', encoding='utf-8')
sys.stdout = output_file

print("Nexus-Scanner Basit Port Tarama Testi")
print("=====================================")

try:
    # Nmap tarayıcısını başlat - tam yol ile
    nm = nmap.PortScanner(nmap_search_path=["C:\\Program Files (x86)\\Nmap\\"])
    print("Nmap tarayıcısı başarıyla başlatıldı.")
    
    # Basit bir tarama gerçekleştir
    print("\nLocalhost üzerinde 80,443,22,21,25 portları taranıyor...")
    nm.scan('127.0.0.1', '80,443,22,21,25')
    
    # Sonuçları yazdır
    print("\nTarama sonuçları:")
    print("=================\n")
    
    # Tüm hostları kontrol et
    for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"Durum: {nm[host].state()}")
        
        # Protokolleri kontrol et
        for proto in nm[host].all_protocols():
            print(f"\nProtokol: {proto}")
            
            # Portları listele
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port {port}\t{proto}\t{nm[host][proto][port]['state']}\t{nm[host][proto][port].get('name', '')}")
    
    print("\nTarama başarıyla tamamlandı!")
    
except Exception as e:
    print(f"Hata oluştu: {str(e)}")

# Dosyayı kapat
sys.stdout = sys.__stdout__
output_file.close()

print("Tarama tamamlandı. Sonuçlar 'scan_results.txt' dosyasına kaydedildi.")