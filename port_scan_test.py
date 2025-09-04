import nmap

def simple_port_scan(target="127.0.0.1", ports="22-100"):
    print(f"Hedef: {target} üzerinde {ports} portları taranıyor...")
    
    # Nmap tarayıcısını başlat
    nm = nmap.PortScanner()
    
    try:
        # Taramayı gerçekleştir
        result = nm.scan(target, ports)
        
        print("\nTarama sonuçları:")
        print("=================")
        
        # Sonuçları kontrol et
        if target in nm.all_hosts():
            print(f"\nHost: {target} ({nm[target].hostname()})")
            print(f"Durum: {nm[target].state()}")
            
            # Protokolleri kontrol et
            for proto in nm[target].all_protocols():
                print(f"\nProtokol: {proto}")
                
                # Portları listele
                ports = nm[target][proto].keys()
                sorted_ports = sorted(ports)
                
                for port in sorted_ports:
                    service = nm[target][proto][port]
                    print(f"Port {port}\t{proto}\t{service['state']}\t{service.get('name', '')}")
        else:
            print(f"Hedef {target} taranamadı veya yanıt vermedi.")
            
    except Exception as e:
        print(f"Hata oluştu: {str(e)}")
    
    print("\nTarama tamamlandı!")

if __name__ == "__main__":
    simple_port_scan()