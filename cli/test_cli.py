#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner CLI Tests
Komut satırı arayüzü test modülü

Bu modül CLI fonksiyonlarını test eder:
- Komut çalıştırma testleri
- Konfigürasyon testleri
- Geçmiş yönetimi testleri
- Utility fonksiyon testleri
"""

import os
import sys
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

# Test imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from cli.main import cli, CLIConfig, CLIHistory
    from cli import NexusCLI, run_cli, create_cli_app, get_cli_version, CLIUtils
except ImportError as e:
    pytest.skip(f"CLI modülü import edilemedi: {e}", allow_module_level=True)

class TestCLIConfig:
    """CLI konfigürasyon testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "config.json"
        self.history_file = Path(self.temp_dir) / "history.json"
    
    def teardown_method(self):
        """Test temizleme"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_creation(self):
        """Konfigürasyon oluşturma testi"""
        config = CLIConfig()
        assert config.config is not None
        assert isinstance(config.config, dict)
        assert 'database_url' in config.config
        assert 'reports_dir' in config.config
    
    def test_config_save_load(self):
        """Konfigürasyon kaydetme/yükleme testi"""
        config = CLIConfig()
        config.config_file = self.config_file
        
        # Test verisi
        test_config = {
            'database_url': 'test://localhost',
            'timeout': 60,
            'debug': True
        }
        
        config.save_config(test_config)
        assert self.config_file.exists()
        
        # Yeniden yükle
        new_config = CLIConfig()
        new_config.config_file = self.config_file
        loaded_config = new_config.load_config()
        
        assert loaded_config['database_url'] == 'test://localhost'
        assert loaded_config['timeout'] == 60
        assert loaded_config['debug'] is True
    
    def test_config_get_set(self):
        """Konfigürasyon get/set testi"""
        config = CLIConfig()
        config.config_file = self.config_file
        
        # Set test
        config.set('test_key', 'test_value')
        assert config.get('test_key') == 'test_value'
        
        # Default value test
        assert config.get('nonexistent_key', 'default') == 'default'
        assert config.get('nonexistent_key') is None

class TestCLIHistory:
    """CLI geçmiş testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = CLIConfig()
        self.config.config_dir = Path(self.temp_dir)
        self.config.history_file = Path(self.temp_dir) / "history.json"
    
    def teardown_method(self):
        """Test temizleme"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_history_creation(self):
        """Geçmiş oluşturma testi"""
        history = CLIHistory(self.config)
        assert history.history is not None
        assert isinstance(history.history, list)
    
    def test_add_command(self):
        """Komut ekleme testi"""
        history = CLIHistory(self.config)
        
        history.add_command('test_command', {'arg1': 'value1'}, 'success')
        
        assert len(history.history) == 1
        entry = history.history[0]
        assert entry['command'] == 'test_command'
        assert entry['args']['arg1'] == 'value1'
        assert entry['result'] == 'success'
        assert 'timestamp' in entry
    
    def test_history_persistence(self):
        """Geçmiş kalıcılık testi"""
        history1 = CLIHistory(self.config)
        history1.add_command('command1', {'test': True})
        history1.save_history()
        
        # Yeni instance oluştur
        history2 = CLIHistory(self.config)
        loaded_history = history2.load_history()
        
        assert len(loaded_history) == 1
        assert loaded_history[0]['command'] == 'command1'
        assert loaded_history[0]['args']['test'] is True

class TestCLICommands:
    """CLI komut testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.runner = CliRunner()
    
    def test_cli_help(self):
        """CLI yardım testi"""
        result = self.runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'Nexus-Scanner' in result.output
    
    def test_version_command(self):
        """Sürüm komutu testi"""
        result = self.runner.invoke(cli, ['version'])
        assert result.exit_code == 0
        assert '1.0.0' in result.output
    
    def test_config_show_command(self):
        """Konfigürasyon gösterme komutu testi"""
        result = self.runner.invoke(cli, ['config', 'show'])
        assert result.exit_code == 0
    
    def test_config_set_command(self):
        """Konfigürasyon ayarlama komutu testi"""
        result = self.runner.invoke(cli, ['config', 'set', 'test_key', 'test_value'])
        assert result.exit_code == 0
    
    def test_stats_command(self):
        """İstatistik komutu testi"""
        result = self.runner.invoke(cli, ['stats'])
        assert result.exit_code == 0
    
    def test_history_command(self):
        """Geçmiş komutu testi"""
        result = self.runner.invoke(cli, ['history'])
        assert result.exit_code == 0

class TestTargetCommands:
    """Hedef yönetimi komut testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.runner = CliRunner()
    
    def test_target_add_command(self):
        """Hedef ekleme komutu testi"""
        result = self.runner.invoke(cli, [
            'target', 'add', 'test-target', 'https://example.com',
            '--description', 'Test target',
            '--type', 'web'
        ])
        assert result.exit_code == 0
        assert 'başarıyla eklendi' in result.output
    
    def test_target_list_command(self):
        """Hedef listeleme komutu testi"""
        result = self.runner.invoke(cli, ['target', 'list'])
        assert result.exit_code == 0
    
    def test_target_list_json_format(self):
        """Hedef listeleme JSON format testi"""
        result = self.runner.invoke(cli, ['target', 'list', '--format', 'json'])
        assert result.exit_code == 0
    
    def test_target_remove_command_with_force(self):
        """Hedef silme komutu (force) testi"""
        result = self.runner.invoke(cli, ['target', 'remove', '1', '--force'])
        assert result.exit_code == 0

class TestScanCommands:
    """Tarama komut testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.runner = CliRunner()
    
    def test_scan_start_command(self):
        """Tarama başlatma komutu testi"""
        result = self.runner.invoke(cli, [
            'scan', 'start', '1',
            '--type', 'web',
            '--threads', '5',
            '--timeout', '30'
        ])
        assert result.exit_code == 0
        assert 'taraması başlatılıyor' in result.output
    
    def test_scan_list_command(self):
        """Tarama listeleme komutu testi"""
        result = self.runner.invoke(cli, ['scan', 'list'])
        assert result.exit_code == 0
    
    def test_scan_list_with_status_filter(self):
        """Tarama listeleme durum filtresi testi"""
        result = self.runner.invoke(cli, ['scan', 'list', '--status', 'completed'])
        assert result.exit_code == 0

class TestReportCommands:
    """Rapor komut testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.runner = CliRunner()
    
    def test_report_generate_command(self):
        """Rapor oluşturma komutu testi"""
        result = self.runner.invoke(cli, [
            'report', 'generate', '1',
            '--format', 'html',
            '--output', 'test_report.html'
        ])
        assert result.exit_code == 0
        assert 'raporu oluşturuluyor' in result.output
    
    def test_report_generate_pdf(self):
        """PDF rapor oluşturma testi"""
        result = self.runner.invoke(cli, [
            'report', 'generate', '1',
            '--format', 'pdf'
        ])
        assert result.exit_code == 0
    
    def test_report_generate_json(self):
        """JSON rapor oluşturma testi"""
        result = self.runner.invoke(cli, [
            'report', 'generate', '1',
            '--format', 'json'
        ])
        assert result.exit_code == 0

class TestNexusCLI:
    """NexusCLI sınıf testleri"""
    
    def test_nexus_cli_creation(self):
        """NexusCLI oluşturma testi"""
        nexus_cli = NexusCLI()
        assert nexus_cli is not None
        assert nexus_cli.config is not None
    
    def test_nexus_cli_with_config_path(self):
        """Konfigürasyon yolu ile NexusCLI testi"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'test': 'config'}, f)
            config_path = f.name
        
        try:
            nexus_cli = NexusCLI(config_path=config_path)
            assert nexus_cli.config_path == config_path
        finally:
            os.unlink(config_path)
    
    def test_get_config(self):
        """Konfigürasyon alma testi"""
        nexus_cli = NexusCLI()
        config = nexus_cli.get_config()
        assert config is not None
        assert isinstance(config, dict)
    
    def test_get_history(self):
        """Geçmiş alma testi"""
        nexus_cli = NexusCLI()
        history = nexus_cli.get_history()
        assert history is not None
        assert isinstance(history, list)

class TestCLIUtils:
    """CLI yardımcı fonksiyon testleri"""
    
    def test_validate_url(self):
        """URL doğrulama testi"""
        # Geçerli URL'ler
        assert CLIUtils.validate_url('https://example.com') is True
        assert CLIUtils.validate_url('http://localhost:8080') is True
        assert CLIUtils.validate_url('https://sub.domain.com/path') is True
        
        # Geçersiz URL'ler
        assert CLIUtils.validate_url('invalid-url') is False
        assert CLIUtils.validate_url('ftp://example.com') is False
        assert CLIUtils.validate_url('') is False
    
    def test_validate_ip(self):
        """IP doğrulama testi"""
        # Geçerli IP'ler
        assert CLIUtils.validate_ip('192.168.1.1') is True
        assert CLIUtils.validate_ip('127.0.0.1') is True
        assert CLIUtils.validate_ip('::1') is True
        
        # Geçersiz IP'ler
        assert CLIUtils.validate_ip('256.256.256.256') is False
        assert CLIUtils.validate_ip('invalid-ip') is False
        assert CLIUtils.validate_ip('') is False
    
    def test_format_duration(self):
        """Süre formatlama testi"""
        assert CLIUtils.format_duration(0) == '00:00'
        assert CLIUtils.format_duration(30) == '00:30'
        assert CLIUtils.format_duration(90) == '01:30'
        assert CLIUtils.format_duration(3661) == '01:01:01'
    
    def test_format_file_size(self):
        """Dosya boyutu formatlama testi"""
        assert CLIUtils.format_file_size(0) == '0 B'
        assert CLIUtils.format_file_size(1024) == '1.0 KB'
        assert CLIUtils.format_file_size(1048576) == '1.0 MB'
        assert CLIUtils.format_file_size(1073741824) == '1.0 GB'
    
    def test_get_terminal_size(self):
        """Terminal boyutu alma testi"""
        size = CLIUtils.get_terminal_size()
        assert isinstance(size, tuple)
        assert len(size) == 2
        assert size[0] > 0  # width
        assert size[1] > 0  # height

class TestCLIFunctions:
    """CLI fonksiyon testleri"""
    
    def test_run_cli(self):
        """CLI çalıştırma testi"""
        # Help komutu test
        result = run_cli(['--help'])
        assert result == 0
    
    def test_create_cli_app(self):
        """CLI uygulaması oluşturma testi"""
        app = create_cli_app()
        assert app is not None
        assert isinstance(app, NexusCLI)
    
    def test_create_cli_app_with_config(self):
        """Konfigürasyon ile CLI uygulaması oluşturma testi"""
        config = {'test_key': 'test_value'}
        app = create_cli_app(config)
        assert app is not None
        assert app.get_config()['test_key'] == 'test_value'
    
    def test_get_cli_version(self):
        """CLI sürüm bilgisi testi"""
        version_info = get_cli_version()
        assert isinstance(version_info, dict)
        assert 'version' in version_info
        assert 'author' in version_info
        assert 'license' in version_info
        assert version_info['version'] == '1.0.0'

class TestCLIIntegration:
    """CLI entegrasyon testleri"""
    
    def setup_method(self):
        """Test kurulumu"""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Test temizleme"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_full_workflow(self):
        """Tam workflow testi"""
        # 1. Hedef ekle
        result = self.runner.invoke(cli, [
            'target', 'add', 'integration-test', 'https://example.com'
        ])
        assert result.exit_code == 0
        
        # 2. Hedefleri listele
        result = self.runner.invoke(cli, ['target', 'list'])
        assert result.exit_code == 0
        
        # 3. Tarama başlat
        result = self.runner.invoke(cli, ['scan', 'start', '1'])
        assert result.exit_code == 0
        
        # 4. Taramaları listele
        result = self.runner.invoke(cli, ['scan', 'list'])
        assert result.exit_code == 0
        
        # 5. Rapor oluştur
        result = self.runner.invoke(cli, ['report', 'generate', '1'])
        assert result.exit_code == 0
        
        # 6. İstatistikleri göster
        result = self.runner.invoke(cli, ['stats'])
        assert result.exit_code == 0
    
    def test_config_persistence(self):
        """Konfigürasyon kalıcılık testi"""
        # Konfigürasyon ayarla
        result = self.runner.invoke(cli, ['config', 'set', 'test_setting', 'test_value'])
        assert result.exit_code == 0
        
        # Konfigürasyonu göster
        result = self.runner.invoke(cli, ['config', 'show'])
        assert result.exit_code == 0
        assert 'test_setting' in result.output
    
    def test_error_handling(self):
        """Hata yönetimi testi"""
        # Geçersiz komut
        result = self.runner.invoke(cli, ['invalid-command'])
        assert result.exit_code != 0
        
        # Geçersiz parametreler
        result = self.runner.invoke(cli, ['target', 'add'])
        assert result.exit_code != 0

# Performance testleri
class TestCLIPerformance:
    """CLI performans testleri"""
    
    def test_command_response_time(self):
        """Komut yanıt süresi testi"""
        import time
        
        runner = CliRunner()
        
        start_time = time.time()
        result = runner.invoke(cli, ['--help'])
        end_time = time.time()
        
        response_time = end_time - start_time
        
        assert result.exit_code == 0
        assert response_time < 2.0  # 2 saniyeden az olmalı
    
    def test_large_output_handling(self):
        """Büyük çıktı yönetimi testi"""
        runner = CliRunner()
        
        # Büyük liste komutu
        result = runner.invoke(cli, ['target', 'list', '--format', 'json'])
        assert result.exit_code == 0
        
        # Çıktı boyutu kontrolü
        assert len(result.output) > 0

# Pytest configuration
def pytest_configure(config):
    """Pytest konfigürasyonu"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m "not slow"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )

# Test runner
if __name__ == "__main__":
    print("🧪 Nexus-Scanner CLI Tests")
    print("=" * 40)
    
    # Pytest'i çalıştır
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--color=yes"
    ])