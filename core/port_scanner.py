import nmap
from typing import Dict, List, Any, Optional
import socket

class PortScanner:
    """
    Port tarama işlemlerini gerçekleştiren sınıf.
    NexusScanner'ın port tarama yeteneklerini genişletir.
    """
    def __init__(self):
        """
        PortScanner sınıfını başlatır.
        """
        self.nm = nmap.PortScanner()
    
    def scan_ports(self, target: str, port_range: str = "1-1000", arguments: str = "-sV") -> Dict[str, Any]:
        """
        Belirtilen hedefte port taraması yapar.
        
        Args:
            target: Taranacak hedef (IP adresi veya domain adı)
            port_range: Taranacak port aralığı (örn. "1-1000" veya "22,80,443")
            arguments: Nmap için ek argümanlar
            
        Returns:
            Tarama sonuçlarını içeren sözlük
        """
        try:
            # Hedef geçerli mi kontrol et
            self._validate_target(target)
            
            # Port taramasını gerçekleştir
            result = self.nm.scan(target, port_range, arguments=arguments)
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def get_open_ports(self, target: str, scan_result: Dict[str, Any] = None) -> List[int]:
        """
        Açık portların listesini döndürür.
        
        Args:
            target: Taranmış hedef
            scan_result: Önceki tarama sonucu (varsa)
            
        Returns:
            Açık portların listesi
        """
        open_ports = []
        
        if scan_result is None and target in self.nm.all_hosts():
            scan_result = self.nm[target]
        
        if scan_result and target in self.nm.all_hosts():
            for proto in self.nm[target].all_protocols():
                ports = self.nm[target][proto].keys()
                for port in ports:
                    if self.nm[target][proto][port]['state'] == 'open':
                        open_ports.append(int(port))
        
        return sorted(open_ports)
    
    def _validate_target(self, target: str) -> bool:
        """
        Hedefin geçerli bir IP adresi veya domain adı olup olmadığını kontrol eder.
        
        Args:
            target: Kontrol edilecek hedef
            
        Returns:
            Hedef geçerliyse True, değilse False
            
        Raises:
            ValueError: Hedef geçerli değilse
        """
        try:
            # IP adresi mi kontrol et
            socket.inet_aton(target)
            return True
        except socket.error:
            # Domain adı mı kontrol et
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                raise ValueError(f"Geçersiz hedef: {target}. Lütfen geçerli bir IP adresi veya domain adı girin.")