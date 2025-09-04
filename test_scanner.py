from core.scanner import NexusScanner

def test_port_scan():
    print("Nexus-Scanner Test Başlatılıyor...")
    print("=============================")
    
    # Localhost üzerinde test taraması yap
    target = "127.0.0.1"
    scanner = NexusScanner(target)
    
    print(f"\n[+] {target} hedefi üzerinde port taraması yapılıyor...")
    scan_result = scanner.port_scan("1-1000")
    
    print("\n[+] Tespit edilen servisler:")
    services = scanner.service_detection()
    
    if services:
        for service in services:
            print(f"  - Port {service['port']}/{service['protocol']}: {service['service']} ({service['state']})")
    else:
        print("  Açık port bulunamadı veya servis tespit edilemedi.")
    
    print("\n[+] Tarama tamamlandı!")
    

if __name__ == "__main__":
    test_port_scan()