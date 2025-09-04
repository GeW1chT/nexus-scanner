#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner CLI Module
Komut satırı arayüzü modülü

Bu modül Nexus-Scanner'ın CLI arayüzünü sağlar:
- Komut satırı araçları
- İnteraktif mod
- Konfigürasyon yönetimi
- Batch işlemler
"""

import os
import sys
from typing import Optional, Dict, Any, List
from pathlib import Path

# Version info
__version__ = "1.0.0"
__author__ = "Nexus-Scanner Team"
__email__ = "info@nexus-scanner.com"
__license__ = "MIT"
__description__ = "Nexus-Scanner Command Line Interface"

# Module exports
__all__ = [
    'NexusCLI',
    'CLIConfig',
    'CLIHistory',
    'run_cli',
    'create_cli_app',
    'get_cli_version',
    'setup_cli_logging'
]

# Import main components
try:
    from .main import cli, CLIConfig, CLIHistory
except ImportError as e:
    print(f"⚠️ CLI modül import hatası: {e}")
    cli = None
    CLIConfig = None
    CLIHistory = None

class NexusCLI:
    """Nexus-Scanner CLI ana sınıfı"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        CLI uygulamasını başlat
        
        Args:
            config_path: Konfigürasyon dosyası yolu
        """
        self.config_path = config_path
        self.config = None
        self.history = None
        self._setup()
    
    def _setup(self):
        """CLI kurulumu"""
        try:
            # Konfigürasyon yükle
            if CLIConfig:
                self.config = CLIConfig()
                if self.config_path:
                    self.config.config_file = Path(self.config_path)
                    self.config.config = self.config.load_config()
            
            # Geçmiş yükle
            if CLIHistory and self.config:
                self.history = CLIHistory(self.config)
            
        except Exception as e:
            print(f"❌ CLI kurulum hatası: {e}")
    
    def run(self, args: Optional[List[str]] = None):
        """CLI uygulamasını çalıştır"""
        if not cli:
            print("❌ CLI modülü yüklenemedi")
            return 1
        
        try:
            if args:
                return cli(args)
            else:
                return cli()
        except Exception as e:
            print(f"❌ CLI çalıştırma hatası: {e}")
            return 1
    
    def get_config(self) -> Optional[Dict[str, Any]]:
        """Mevcut konfigürasyonu döndür"""
        return self.config.config if self.config else None
    
    def get_history(self) -> Optional[List[Dict[str, Any]]]:
        """Komut geçmişini döndür"""
        return self.history.history if self.history else None

def run_cli(args: Optional[List[str]] = None, config_path: Optional[str] = None) -> int:
    """
    CLI uygulamasını çalıştır
    
    Args:
        args: Komut satırı argümanları
        config_path: Konfigürasyon dosyası yolu
    
    Returns:
        Çıkış kodu (0: başarılı, 1: hata)
    """
    try:
        nexus_cli = NexusCLI(config_path)
        return nexus_cli.run(args)
    except KeyboardInterrupt:
        print("\n👋 İşlem iptal edildi.")
        return 130
    except Exception as e:
        print(f"❌ CLI hatası: {e}")
        return 1

def create_cli_app(config: Optional[Dict[str, Any]] = None) -> Optional[NexusCLI]:
    """
    CLI uygulaması oluştur
    
    Args:
        config: Konfigürasyon sözlüğü
    
    Returns:
        NexusCLI instance veya None
    """
    try:
        nexus_cli = NexusCLI()
        
        if config and nexus_cli.config:
            nexus_cli.config.config.update(config)
            nexus_cli.config.save_config()
        
        return nexus_cli
    except Exception as e:
        print(f"❌ CLI uygulaması oluşturulamadı: {e}")
        return None

def get_cli_version() -> Dict[str, str]:
    """
    CLI sürüm bilgilerini döndür
    
    Returns:
        Sürüm bilgileri sözlüğü
    """
    return {
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "description": __description__,
        "python_version": sys.version.split()[0],
        "platform": sys.platform
    }

def setup_cli_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> bool:
    """
    CLI logging kurulumu
    
    Args:
        log_level: Log seviyesi (DEBUG, INFO, WARNING, ERROR)
        log_file: Log dosyası yolu (opsiyonel)
    
    Returns:
        Kurulum başarılı mı
    """
    try:
        import logging
        from rich.logging import RichHandler
        
        # Log seviyesi ayarla
        level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Handler'ları ayarla
        handlers = [RichHandler(rich_tracebacks=True)]
        
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
            handlers.append(file_handler)
        
        # Logging konfigürasyonu
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=handlers
        )
        
        return True
        
    except Exception as e:
        print(f"❌ Logging kurulum hatası: {e}")
        return False

# CLI utilities
class CLIUtils:
    """CLI yardımcı fonksiyonları"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """URL doğrulama"""
        try:
            import validators
            return validators.url(url) is True
        except ImportError:
            import re
            pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domain...
                r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # host...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            return pattern.match(url) is not None
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """IP adresi doğrulama"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def format_duration(seconds: int) -> str:
        """Süreyi formatla"""
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            return f"{minutes:02d}:{seconds:02d}"
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Dosya boyutunu formatla"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    @staticmethod
    def get_terminal_size() -> tuple:
        """Terminal boyutunu al"""
        try:
            import shutil
            return shutil.get_terminal_size()
        except Exception:
            return (80, 24)  # Default size

# CLI test utilities
class CLITester:
    """CLI test yardımcıları"""
    
    def __init__(self):
        self.test_config = {
            "database_url": "sqlite:///:memory:",
            "reports_dir": "./test_reports",
            "log_level": "DEBUG",
            "timeout": 10
        }
    
    def create_test_cli(self) -> Optional[NexusCLI]:
        """Test CLI oluştur"""
        return create_cli_app(self.test_config)
    
    def run_test_command(self, command: str) -> int:
        """Test komutu çalıştır"""
        test_cli = self.create_test_cli()
        if not test_cli:
            return 1
        
        args = command.split()
        return test_cli.run(args)

# Module initialization
def _initialize_module():
    """Modül başlatma"""
    try:
        # CLI dizinini oluştur
        cli_dir = Path.home() / ".nexus-scanner"
        cli_dir.mkdir(parents=True, exist_ok=True)
        
        # Log dizinini oluştur
        log_dir = cli_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        return True
    except Exception as e:
        print(f"⚠️ CLI modül başlatma hatası: {e}")
        return False

# Initialize on import
_initialize_module()

# CLI entry point
def main():
    """Ana CLI giriş noktası"""
    return run_cli()

if __name__ == "__main__":
    sys.exit(main())