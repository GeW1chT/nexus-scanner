import nmap
import socket
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional

class NexusScanner:
    """
    Ana scanner sınıfı - Nexus-Scanner'ın temel tarama işlevselliğini sağlar.
    """
    def __init__(self, target: str):
        """
        Scanner'ı başlatır.
        
        Args:
            target: Taranacak hedef (IP adresi veya domain adı)
        """
        self.target = target
        self.nm = nmap.PortScanner()
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_results': {},
            'vulnerabilities': []
        }
    
    def port_scan(self, port_range: str = "1-1000") -> Dict:
        """
        Temel port taraması yapar.
        
        Args:
            port_range: Taranacak port aralığı (örn. "1-1000" veya "22,80,443")
            
        Returns:
            Tarama sonuçlarını içeren sözlük
        """
        print(f"🔍 {self.target} hedefi taranıyor...")
        try:
            scan_result = self.nm.scan(self.target, port_range)
            self.results['scan_results'] = scan_result
            return scan_result
        except Exception as e:
            print(f"❌ Tarama sırasında hata oluştu: {str(e)}")
            return {'error': str(e)}
    
    def service_detection(self) -> List[Dict]:
        """
        Açık portlarda çalışan servisleri tespit eder.
        
        Returns:
            Tespit edilen servislerin listesi
        """
        services = []
        try:
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service_info = self.nm[host][proto][port]
                        services.append({
                            'port': port,
                            'protocol': proto,
                            'state': service_info['state'],
                            'service': service_info.get('name', 'unknown'),
                            'version': service_info.get('version', '')
                        })
            self.results['services'] = services
            return services
        except Exception as e:
            print(f"❌ Servis tespiti sırasında hata oluştu: {str(e)}")
            return []
    
    def check_common_vulnerabilities(self) -> List[Dict]:
        """
        Tespit edilen servislerde yaygın güvenlik açıklarını kontrol eder.
        
        Returns:
            Tespit edilen güvenlik açıklarının listesi
        """
        vulnerabilities = []
        # Bu fonksiyon ileride genişletilecek
        # Örnek olarak, açık SSH portlarında eski sürüm kontrolü yapılabilir
        return vulnerabilities
    
    def get_results(self) -> Dict:
        """
        Tüm tarama sonuçlarını döndürür.
        
        Returns:
            Tarama sonuçlarını içeren sözlük
        """
        return self.results


if __name__ == "__main__":
    # Test amaçlı basit bir kullanım örneği
    scanner = NexusScanner("127.0.0.1")
    scanner.port_scan("22-100")
    services = scanner.service_detection()
    print(f"\nTespit edilen servisler: {services}")
    print("\nTarama tamamlandı!")