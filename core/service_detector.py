from typing import Dict, List, Any, Optional
import nmap
import socket
import requests

class ServiceDetector:
    """
    Açık portlarda çalışan servisleri tespit eden sınıf.
    """
    def __init__(self):
        """
        ServiceDetector sınıfını başlatır.
        """
        self.nm = nmap.PortScanner()
        self.common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy'
        }
    
    def detect_services(self, target: str, scan_result: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Hedefte çalışan servisleri tespit eder.
        
        Args:
            target: Hedef IP adresi veya domain adı
            scan_result: Önceki tarama sonucu (varsa)
            
        Returns:
            Tespit edilen servislerin listesi
        """
        services = []
        
        if scan_result is None:
            try:
                # Servis tespiti için tarama yap
                self.nm.scan(target, arguments="-sV")
            except Exception as e:
                return [{'error': str(e)}]
        
        if target in self.nm.all_hosts():
            for proto in self.nm[target].all_protocols():
                ports = self.nm[target][proto].keys()
                for port in ports:
                    service_info = self.nm[target][proto][port]
                    if service_info['state'] == 'open':
                        service = {
                            'port': port,
                            'protocol': proto,
                            'service': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        }
                        services.append(service)
        
        return services
    
    def get_service_details(self, port: int, service_name: str) -> Dict[str, Any]:
        """
        Belirli bir servis hakkında daha fazla bilgi sağlar.
        
        Args:
            port: Servisin çalıştığı port
            service_name: Servis adı
            
        Returns:
            Servis hakkında detaylı bilgi
        """
        details = {
            'port': port,
            'service': service_name,
            'common_vulnerabilities': [],
            'security_recommendations': []
        }
        
        # Servise özel bilgileri ekle
        if service_name.lower() == 'http' or service_name.lower() == 'https':
            details['common_vulnerabilities'] = [
                'SQL Injection',
                'Cross-Site Scripting (XSS)',
                'Cross-Site Request Forgery (CSRF)',
                'Broken Authentication'
            ]
            details['security_recommendations'] = [
                'Güncel web sunucusu kullanın',
                'HTTPS kullanın ve SSL/TLS yapılandırmasını güçlendirin',
                'Güvenlik başlıklarını ekleyin (X-XSS-Protection, Content-Security-Policy)',
                'Web Application Firewall (WAF) kullanın'
            ]
        elif service_name.lower() == 'ssh':
            details['common_vulnerabilities'] = [
                'Brute Force Saldırıları',
                'Zayıf Şifreleme Algoritmaları',
                'Eski SSH Sürümleri'
            ]
            details['security_recommendations'] = [
                'SSH sürümünü güncel tutun',
                'Şifre tabanlı kimlik doğrulama yerine anahtar tabanlı kimlik doğrulama kullanın',
                'Başarısız giriş denemelerini sınırlayın',
                'Root girişini devre dışı bırakın'
            ]
        
        return details
    
    def check_http_headers(self, target: str, port: int = 80) -> Dict[str, Any]:
        """
        HTTP başlıklarını kontrol eder ve güvenlik değerlendirmesi yapar.
        
        Args:
            target: Hedef IP adresi veya domain adı
            port: HTTP servisinin çalıştığı port
            
        Returns:
            HTTP başlıkları ve güvenlik değerlendirmesi
        """
        result = {
            'headers': {},
            'security_issues': [],
            'recommendations': []
        }
        
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{target}:{port}"
        
        try:
            response = requests.get(url, timeout=5, verify=False)
            result['headers'] = dict(response.headers)
            
            # Güvenlik başlıklarını kontrol et
            security_headers = {
                'Strict-Transport-Security': 'HSTS eksik, HTTPS bağlantılarını zorunlu kılmak için ekleyin',
                'X-Content-Type-Options': 'X-Content-Type-Options eksik, MIME türü koruması için "nosniff" değeriyle ekleyin',
                'X-Frame-Options': 'X-Frame-Options eksik, clickjacking saldırılarını önlemek için ekleyin',
                'Content-Security-Policy': 'Content-Security-Policy eksik, XSS saldırılarını önlemek için ekleyin',
                'X-XSS-Protection': 'X-XSS-Protection eksik, tarayıcı XSS koruması için ekleyin'
            }
            
            for header, message in security_headers.items():
                if header not in result['headers']:
                    result['security_issues'].append(message)
                    result['recommendations'].append(f'{header} başlığını ekleyin')
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result