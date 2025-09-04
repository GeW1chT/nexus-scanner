#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Advanced Port Scanner Module
Profesyonel siber güvenlik aracı - Gelişmiş port tarama

Bu modül hedef sistemlerde açık portları ve servisleri tespit eder.
"""

import socket
import threading
import time
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import ipaddress

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ python-nmap modülü bulunamadı. Temel tarama modu kullanılacak.")

@dataclass
class PortResult:
    """Port tarama sonucu"""
    host: str
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    response_time: float = 0.0
    risk_level: str = "info"  # info, low, medium, high, critical

class AdvancedPortScanner:
    """Gelişmiş port tarayıcısı"""
    
    def __init__(self, timeout: float = 3.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        
        # Yaygın portlar ve servisleri
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
        }
        
        # Risk seviyesi yüksek portlar
        self.high_risk_ports = {
            21: "FTP - Şifresiz veri transferi",
            23: "Telnet - Şifresiz uzak erişim", 
            135: "RPC - Windows servis açığı",
            139: "NetBIOS - Bilgi sızıntısı riski",
            445: "SMB - Ransomware vektörü",
            1433: "MSSQL - Veritabanı erişimi",
            3389: "RDP - Brute force hedefi",
            5900: "VNC - Zayıf kimlik doğrulama"
        }
        
        # Banner grabbing için yaygın servisler
        self.banner_services = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
    
    def scan_host(self, host: str, ports: List[int] = None, 
                  scan_type: str = "tcp", service_detection: bool = True) -> List[PortResult]:
        """Tek bir host için port taraması yapar"""
        
        if ports is None:
            ports = list(self.common_ports.keys())
        
        print(f"🎯 Port taraması başlatılıyor: {host}")
        print(f"📋 {len(ports)} port taranacak ({scan_type.upper()})")
        
        results = []
        
        if NMAP_AVAILABLE and service_detection:
            # Nmap ile gelişmiş tarama
            results = self._nmap_scan(host, ports, scan_type)
        else:
            # Temel socket taraması
            results = self._socket_scan(host, ports, scan_type)
        
        # Sonuçları risk seviyesine göre sırala
        results.sort(key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}[x.risk_level],
            x.port
        ))
        
        return results
    
    def _nmap_scan(self, host: str, ports: List[int], scan_type: str) -> List[PortResult]:
        """Nmap ile gelişmiş port taraması"""
        
        port_range = ','.join(map(str, ports))
        
        # Nmap tarama argümanları
        if scan_type == "tcp":
            arguments = f'-sS -sV -O --script=default -p {port_range}'
        elif scan_type == "udp":
            arguments = f'-sU -sV -p {port_range}'
        else:
            arguments = f'-sS -p {port_range}'
        
        try:
            print(f"  🔍 Nmap taraması: {arguments}")
            self.nm.scan(host, arguments=arguments)
            
            results = []
            
            for scanned_host in self.nm.all_hosts():
                for protocol in self.nm[scanned_host].all_protocols():
                    ports_info = self.nm[scanned_host][protocol].keys()
                    
                    for port in ports_info:
                        port_info = self.nm[scanned_host][protocol][port]
                        
                        # Servis bilgilerini al
                        service = port_info.get('name', 'unknown')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        
                        if product and version:
                            version = f"{product} {version}"
                        elif product:
                            version = product
                        
                        # Risk seviyesini belirle
                        risk_level = self._determine_risk_level(port, service, port_info)
                        
                        result = PortResult(
                            host=scanned_host,
                            port=port,
                            protocol=protocol,
                            state=port_info['state'],
                            service=service,
                            version=version,
                            banner=port_info.get('extrainfo', ''),
                            risk_level=risk_level
                        )
                        
                        results.append(result)
                        
                        if result.state == 'open':
                            risk_icon = self._get_risk_icon(risk_level)
                            print(f"  {risk_icon} {port}/{protocol} - {service} ({result.state})")
            
            return results
            
        except Exception as e:
            print(f"  ❌ Nmap tarama hatası: {str(e)}")
            return self._socket_scan(host, ports, scan_type)
    
    def _socket_scan(self, host: str, ports: List[int], scan_type: str) -> List[PortResult]:
        """Socket ile temel port taraması"""
        
        results = []
        
        def scan_port(port: int) -> Optional[PortResult]:
            try:
                start_time = time.time()
                
                if scan_type == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        response_time = time.time() - start_time
                        
                        # Banner grabbing dene
                        banner = self._grab_banner(host, port)
                        
                        # Servis tespiti
                        service = self.common_ports.get(port, "unknown")
                        
                        # Risk seviyesi
                        risk_level = "high" if port in self.high_risk_ports else "medium" if port < 1024 else "low"
                        
                        return PortResult(
                            host=host,
                            port=port,
                            protocol="tcp",
                            state="open",
                            service=service,
                            banner=banner,
                            response_time=response_time,
                            risk_level=risk_level
                        )
                
                elif scan_type == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    
                    # UDP için basit paket gönder
                    sock.sendto(b'\x00', (host, port))
                    
                    try:
                        data, addr = sock.recvfrom(1024)
                        sock.close()
                        
                        service = self.common_ports.get(port, "unknown")
                        risk_level = "medium" if port < 1024 else "low"
                        
                        return PortResult(
                            host=host,
                            port=port,
                            protocol="udp",
                            state="open",
                            service=service,
                            banner=data.decode('utf-8', errors='ignore')[:100],
                            risk_level=risk_level
                        )
                    except socket.timeout:
                        # UDP için timeout normal (port açık olabilir)
                        pass
                    finally:
                        sock.close()
                
            except Exception:
                pass
            
            return None
        
        # Multi-threaded tarama
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result and result.state == 'open':
                        results.append(result)
                        risk_icon = self._get_risk_icon(result.risk_level)
                        print(f"  {risk_icon} {port}/{result.protocol} - {result.service} (açık)")
                    
                    completed += 1
                    if completed % 50 == 0:
                        print(f"  📊 İlerleme: {completed}/{len(ports)}")
                        
                except Exception as e:
                    pass
        
        return results
    
    def _grab_banner(self, host: str, port: int) -> str:
        """Belirtilen port için banner grabbing yapar"""
        
        if port not in self.banner_services:
            return ""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            
            # HTTP için özel istek
            if port in [80, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            # HTTPS için temel bağlantı
            elif port in [443]:
                pass  # SSL handshake gerekli
            # Diğer servisler için boş veri
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200]  # İlk 200 karakter
            
        except Exception:
            return ""
    
    def _determine_risk_level(self, port: int, service: str, port_info: Dict) -> str:
        """Port ve servis bilgisine göre risk seviyesi belirler"""
        
        # Kritik güvenlik açıkları
        if port in [135, 139, 445] and port_info.get('state') == 'open':
            return "critical"
        
        # Yüksek risk portları
        if port in self.high_risk_ports:
            return "high"
        
        # Veritabanı portları
        if port in [1433, 1521, 3306, 5432, 6379, 27017]:
            return "high"
        
        # Uzak erişim portları
        if port in [22, 3389, 5900]:
            return "medium"
        
        # Web servisleri
        if port in [80, 443, 8080, 8443]:
            return "low"
        
        # Sistem portları (1-1023)
        if port < 1024:
            return "medium"
        
        return "info"
    
    def _get_risk_icon(self, risk_level: str) -> str:
        """Risk seviyesine göre ikon döndürür"""
        icons = {
            "critical": "🚨",
            "high": "🔴", 
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️"
        }
        return icons.get(risk_level, "❓")
    
    def scan_network(self, network: str, ports: List[int] = None) -> Dict[str, List[PortResult]]:
        """Ağ aralığında port taraması yapar"""
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            
            # Çok büyük ağları sınırla
            if len(hosts) > 254:
                print(f"⚠️ Ağ çok büyük ({len(hosts)} host). İlk 254 host taranacak.")
                hosts = hosts[:254]
            
            print(f"🌐 Ağ taraması: {network} ({len(hosts)} host)")
            
            results = {}
            
            for i, host in enumerate(hosts, 1):
                print(f"\n[{i}/{len(hosts)}] {host} taranıyor...")
                
                # Önce ping kontrolü (hızlı host keşfi)
                if self._ping_host(host):
                    host_results = self.scan_host(host, ports)
                    if host_results:
                        results[host] = host_results
                        print(f"  ✅ {len(host_results)} açık port bulundu")
                    else:
                        print(f"  ℹ️ Açık port bulunamadı")
                else:
                    print(f"  ❌ Host erişilebilir değil")
            
            return results
            
        except ValueError as e:
            print(f"❌ Geçersiz ağ adresi: {network}")
            return {}
    
    def _ping_host(self, host: str) -> bool:
        """Host'un erişilebilir olup olmadığını kontrol eder"""
        try:
            # Windows için ping komutu
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '1000', host],
                capture_output=True,
                text=True,
                timeout=3
            )
            return result.returncode == 0
        except:
            # Ping başarısız olsa da port taraması yap
            return True
    
    def generate_report(self, results: Dict[str, List[PortResult]]) -> Dict[str, Any]:
        """Port tarama sonuçlarından rapor oluşturur"""
        
        total_hosts = len(results)
        total_open_ports = sum(len(ports) for ports in results.values())
        
        # Risk dağılımı
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        service_summary = {}
        port_summary = {}
        
        critical_findings = []
        
        for host, ports in results.items():
            for port_result in ports:
                # Risk dağılımı
                risk_summary[port_result.risk_level] += 1
                
                # Servis dağılımı
                service = port_result.service
                service_summary[service] = service_summary.get(service, 0) + 1
                
                # Port dağılımı
                port_num = port_result.port
                port_summary[port_num] = port_summary.get(port_num, 0) + 1
                
                # Kritik bulgular
                if port_result.risk_level in ['critical', 'high']:
                    critical_findings.append({
                        "host": host,
                        "port": port_result.port,
                        "protocol": port_result.protocol,
                        "service": port_result.service,
                        "version": port_result.version,
                        "risk_level": port_result.risk_level,
                        "description": self.high_risk_ports.get(port_result.port, "Yüksek riskli servis")
                    })
        
        # En yaygın açık portlar
        common_open_ports = sorted(port_summary.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "scan_summary": {
                "total_hosts_scanned": total_hosts,
                "total_open_ports": total_open_ports,
                "average_ports_per_host": round(total_open_ports / total_hosts, 1) if total_hosts > 0 else 0
            },
            "risk_summary": risk_summary,
            "service_summary": dict(sorted(service_summary.items(), key=lambda x: x[1], reverse=True)[:10]),
            "common_open_ports": [{
                "port": port,
                "count": count,
                "service": self.common_ports.get(port, "unknown")
            } for port, count in common_open_ports],
            "critical_findings": critical_findings,
            "recommendations": self._get_port_recommendations(critical_findings, risk_summary)
        }
    
    def _get_port_recommendations(self, critical_findings: List[Dict], 
                                risk_summary: Dict[str, int]) -> List[str]:
        """Port tarama sonuçlarına göre öneriler döndürür"""
        
        recommendations = []
        
        if critical_findings:
            recommendations.extend([
                "🚨 ACIL: Kritik güvenlik açıkları tespit edildi!",
                "✅ Gereksiz servisleri kapatın",
                "✅ Firewall kurallarını gözden geçirin",
                "✅ Erişim kontrollerini sıkılaştırın"
            ])
        
        if risk_summary.get('high', 0) > 0:
            recommendations.extend([
                "⚠️ Yüksek riskli servisler tespit edildi",
                "✅ Güvenlik yamalarını uygulayın",
                "✅ Güçlü kimlik doğrulama kullanın"
            ])
        
        # Genel öneriler
        recommendations.extend([
            "✅ Sadece gerekli portları açık tutun",
            "✅ Düzenli port taramaları yapın",
            "✅ Network segmentasyonu uygulayın",
            "✅ IDS/IPS sistemleri kullanın",
            "✅ Log izleme ve analiz yapın",
            "✅ Penetrasyon testleri düzenleyin"
        ])
        
        return recommendations

# Test fonksiyonu
if __name__ == "__main__":
    scanner = AdvancedPortScanner(max_threads=50)
    
    # Test host'u
    test_host = "scanme.nmap.org"
    
    print("Nexus-Scanner Advanced Port Scanner Test")
    print("=" * 45)
    
    # Yaygın portları tara
    results = scanner.scan_host(test_host, list(scanner.common_ports.keys()))
    
    if results:
        # Rapor oluştur
        report_data = {test_host: results}
        report = scanner.generate_report(report_data)
        
        print("\n📊 Tarama Raporu:")
        print(f"Açık Port Sayısı: {report['scan_summary']['total_open_ports']}")
        
        print("\n🎯 Açık Portlar:")
        for result in results[:10]:  # İlk 10 port
            risk_icon = scanner._get_risk_icon(result.risk_level)
            print(f"  {risk_icon} {result.port}/{result.protocol} - {result.service}")
            if result.version:
                print(f"    Version: {result.version}")
        
        if report['critical_findings']:
            print("\n🚨 Kritik Bulgular:")
            for finding in report['critical_findings'][:5]:
                print(f"  - Port {finding['port']}: {finding['description']}")
        
        print("\n💡 Öneriler:")
        for rec in report['recommendations'][:5]:
            print(f"  {rec}")
    else:
        print("\n❌ Açık port bulunamadı veya host erişilebilir değil.")