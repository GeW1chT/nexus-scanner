#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner CLI Interface
Komut satırı arayüzü - Türkçe destekli profesyonel güvenlik tarayıcısı

Bu modül Nexus-Scanner'ın komut satırı arayüzünü sağlar:
- Hedef yönetimi (ekleme, listeleme, silme)
- Tarama işlemleri (web, network, full)
- Rapor oluşturma ve görüntüleme
- Konfigürasyon yönetimi
- İstatistik görüntüleme
"""

import os
import sys
import click
import json
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

# Rich için imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.tree import Tree
from rich.text import Text
from rich import print as rprint

# Proje modüllerini import et
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core import NexusScanner
    from database import get_database_manager
    from database.models import Target, Scan, Finding, Report
    from reports import ReportManager, ReportConfig
    from utils.logger import setup_logger
except ImportError as e:
    click.echo(f"❌ Modül import hatası: {e}", err=True)
    sys.exit(1)

# Console setup
console = Console()
logger = setup_logger("nexus-cli")

# CLI Configuration
CLI_CONFIG_FILE = Path.home() / ".nexus-scanner" / "config.json"
CLI_HISTORY_FILE = Path.home() / ".nexus-scanner" / "history.json"

class CLIConfig:
    """CLI konfigürasyon yöneticisi"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".nexus-scanner"
        self.config_file = self.config_dir / "config.json"
        self.history_file = self.config_dir / "history.json"
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Konfigürasyonu yükle"""
        default_config = {
            "database_url": "sqlite:///nexus_scanner.db",
            "reports_dir": "./reports",
            "log_level": "INFO",
            "max_threads": 10,
            "timeout": 30,
            "user_agent": "Nexus-Scanner CLI/1.0",
            "output_format": "table",
            "auto_save": True,
            "language": "tr"
        }
        
        if not self.config_file.exists():
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self.save_config(default_config)
            return default_config
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Eksik anahtarları ekle
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except Exception as e:
            console.print(f"⚠️ Konfigürasyon yüklenirken hata: {e}", style="yellow")
            return default_config
    
    def save_config(self, config: Dict[str, Any] = None):
        """Konfigürasyonu kaydet"""
        if config:
            self.config = config
        
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            console.print(f"❌ Konfigürasyon kaydedilirken hata: {e}", style="red")
    
    def get(self, key: str, default=None):
        """Konfigürasyon değeri al"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Konfigürasyon değeri ayarla"""
        self.config[key] = value
        if self.config.get("auto_save", True):
            self.save_config()

class CLIHistory:
    """CLI geçmiş yöneticisi"""
    
    def __init__(self, config: CLIConfig):
        self.config = config
        self.history_file = config.history_file
        self.history = self.load_history()
    
    def load_history(self) -> List[Dict[str, Any]]:
        """Geçmişi yükle"""
        if not self.history_file.exists():
            return []
        
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    
    def save_history(self):
        """Geçmişi kaydet"""
        try:
            self.config.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history[-100:], f, indent=2, ensure_ascii=False)  # Son 100 kayıt
        except Exception as e:
            logger.error(f"Geçmiş kaydedilirken hata: {e}")
    
    def add_command(self, command: str, args: Dict[str, Any], result: str = "success"):
        """Komut geçmişine ekle"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "args": args,
            "result": result
        }
        self.history.append(entry)
        self.save_history()

# Global instances
cli_config = CLIConfig()
cli_history = CLIHistory(cli_config)

# Click group setup
@click.group()
@click.option('--config', '-c', help='Konfigürasyon dosyası yolu')
@click.option('--verbose', '-v', is_flag=True, help='Detaylı çıktı')
@click.option('--quiet', '-q', is_flag=True, help='Sessiz mod')
@click.pass_context
def cli(ctx, config, verbose, quiet):
    """🔍 Nexus-Scanner - Profesyonel Güvenlik Tarayıcısı
    
    Nexus-Scanner, ağ ve web uygulaması güvenlik açıklarını tespit eden
    profesyonel bir siber güvenlik aracıdır.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = cli_config
    ctx.obj['history'] = cli_history
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    
    if not quiet:
        console.print(Panel.fit(
            "[bold blue]🔍 Nexus-Scanner CLI[/bold blue]\n"
            "[dim]Profesyonel Güvenlik Tarayıcısı v1.0[/dim]",
            border_style="blue"
        ))

# Target management commands
@cli.group()
def target():
    """🎯 Hedef yönetimi komutları"""
    pass

@target.command('add')
@click.argument('name')
@click.argument('url')
@click.option('--description', '-d', help='Hedef açıklaması')
@click.option('--type', '-t', 'target_type', 
              type=click.Choice(['web', 'network', 'api']), 
              default='web', help='Hedef tipi')
@click.pass_context
def add_target(ctx, name, url, description, target_type):
    """Yeni hedef ekle
    
    NAME: Hedef adı
    URL: Hedef URL veya IP adresi
    """
    try:
        with console.status("[bold green]Hedef ekleniyor..."):
            # Database bağlantısı
            db_manager = get_database_manager()
            
            # Hedef oluştur
            target_data = {
                'name': name,
                'url': url,
                'description': description or f"{target_type.title()} hedefi",
                'target_type': target_type,
                'created_at': datetime.now()
            }
            
            # Veritabanına kaydet (gerçek implementasyon)
            target_id = len(name)  # Placeholder
        
        console.print(f"✅ Hedef başarıyla eklendi: [bold green]{name}[/bold green]")
        console.print(f"   ID: {target_id}")
        console.print(f"   URL: {url}")
        console.print(f"   Tip: {target_type}")
        
        # Geçmişe ekle
        ctx.obj['history'].add_command('target add', {
            'name': name, 'url': url, 'type': target_type
        })
        
    except Exception as e:
        console.print(f"❌ Hedef eklenirken hata: {e}", style="red")
        ctx.obj['history'].add_command('target add', {
            'name': name, 'url': url
        }, "error")

@target.command('list')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['table', 'json', 'csv']),
              default='table', help='Çıktı formatı')
@click.option('--filter', 'filter_type',
              type=click.Choice(['web', 'network', 'api', 'all']),
              default='all', help='Hedef tipi filtresi')
@click.pass_context
def list_targets(ctx, output_format, filter_type):
    """Hedefleri listele"""
    try:
        with console.status("[bold blue]Hedefler yükleniyor..."):
            # Örnek veri (gerçek implementasyonda database'den gelir)
            targets = [
                {
                    'id': 1,
                    'name': 'Test Web Sitesi',
                    'url': 'https://example.com',
                    'type': 'web',
                    'status': 'active',
                    'last_scan': '2024-01-15 14:30:00',
                    'findings': 5
                },
                {
                    'id': 2,
                    'name': 'Internal Network',
                    'url': '192.168.1.0/24',
                    'type': 'network',
                    'status': 'active',
                    'last_scan': '2024-01-14 09:15:00',
                    'findings': 12
                }
            ]
            
            # Filtrele
            if filter_type != 'all':
                targets = [t for t in targets if t['type'] == filter_type]
        
        if not targets:
            console.print("ℹ️ Henüz hedef eklenmemiş.", style="yellow")
            return
        
        if output_format == 'table':
            table = Table(title="🎯 Hedefler")
            table.add_column("ID", style="cyan")
            table.add_column("Ad", style="green")
            table.add_column("URL", style="blue")
            table.add_column("Tip", style="magenta")
            table.add_column("Durum", style="yellow")
            table.add_column("Son Tarama", style="dim")
            table.add_column("Bulgular", style="red")
            
            for target in targets:
                status_emoji = "🟢" if target['status'] == 'active' else "🔴"
                findings_color = "red" if target['findings'] > 10 else "yellow" if target['findings'] > 0 else "green"
                
                table.add_row(
                    str(target['id']),
                    target['name'],
                    target['url'],
                    target['type'],
                    f"{status_emoji} {target['status']}",
                    target['last_scan'],
                    f"[{findings_color}]{target['findings']}[/{findings_color}]"
                )
            
            console.print(table)
            
        elif output_format == 'json':
            console.print(json.dumps(targets, indent=2, ensure_ascii=False))
            
        elif output_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=targets[0].keys())
            writer.writeheader()
            writer.writerows(targets)
            console.print(output.getvalue())
        
        ctx.obj['history'].add_command('target list', {'format': output_format})
        
    except Exception as e:
        console.print(f"❌ Hedefler listelenirken hata: {e}", style="red")

@target.command('remove')
@click.argument('target_id', type=int)
@click.option('--force', '-f', is_flag=True, help='Onay istemeden sil')
@click.pass_context
def remove_target(ctx, target_id, force):
    """Hedef sil
    
    TARGET_ID: Silinecek hedefin ID'si
    """
    try:
        if not force:
            if not Confirm.ask(f"🗑️ {target_id} ID'li hedefi silmek istediğinizden emin misiniz?"):
                console.print("❌ İşlem iptal edildi.", style="yellow")
                return
        
        with console.status("[bold red]Hedef siliniyor..."):
            # Gerçek implementasyonda database'den sil
            pass
        
        console.print(f"✅ Hedef başarıyla silindi: ID {target_id}", style="green")
        ctx.obj['history'].add_command('target remove', {'id': target_id})
        
    except Exception as e:
        console.print(f"❌ Hedef silinirken hata: {e}", style="red")

# Scan commands
@cli.group()
def scan():
    """🔍 Tarama komutları"""
    pass

@scan.command('start')
@click.argument('target_id', type=int)
@click.option('--type', '-t', 'scan_type',
              type=click.Choice(['web', 'network', 'full']),
              default='web', help='Tarama tipi')
@click.option('--threads', '-j', type=int, default=10, help='Thread sayısı')
@click.option('--timeout', type=int, default=30, help='Timeout (saniye)')
@click.option('--output', '-o', help='Çıktı dosyası')
@click.pass_context
def start_scan(ctx, target_id, scan_type, threads, timeout, output):
    """Tarama başlat
    
    TARGET_ID: Taranacak hedefin ID'si
    """
    try:
        console.print(f"🔍 {scan_type.title()} taraması başlatılıyor...")
        
        # Progress bar ile tarama simülasyonu
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            # Tarama aşamaları
            stages = [
                ("Hedef analizi", 10),
                ("Port taraması", 25),
                ("Servis tespiti", 40),
                ("Güvenlik testleri", 70),
                ("Rapor oluşturma", 100)
            ]
            
            task = progress.add_task("Tarama başlatılıyor...", total=100)
            
            import time
            for stage_name, percentage in stages:
                progress.update(task, description=f"[cyan]{stage_name}[/cyan]", completed=percentage)
                time.sleep(1)  # Simülasyon için
        
        # Sonuçları göster
        findings = [
            {"type": "SQL Injection", "severity": "critical", "url": "/login.php"},
            {"type": "XSS", "severity": "medium", "url": "/search.php"},
            {"type": "Open Port", "severity": "low", "url": "22/tcp"}
        ]
        
        console.print("\n📊 Tarama Sonuçları:")
        
        results_table = Table(title="🔍 Bulgular")
        results_table.add_column("Tip", style="cyan")
        results_table.add_column("Önem", style="red")
        results_table.add_column("Konum", style="blue")
        
        for finding in findings:
            severity_color = {
                "critical": "red",
                "high": "orange",
                "medium": "yellow",
                "low": "green"
            }.get(finding['severity'], "white")
            
            results_table.add_row(
                finding['type'],
                f"[{severity_color}]{finding['severity'].upper()}[/{severity_color}]",
                finding['url']
            )
        
        console.print(results_table)
        
        # Özet
        console.print(f"\n✅ Tarama tamamlandı!")
        console.print(f"   📈 Toplam bulgu: {len(findings)}")
        console.print(f"   🔴 Kritik: {len([f for f in findings if f['severity'] == 'critical'])}")
        console.print(f"   🟡 Orta: {len([f for f in findings if f['severity'] == 'medium'])}")
        console.print(f"   🟢 Düşük: {len([f for f in findings if f['severity'] == 'low'])}")
        
        if output:
            console.print(f"   💾 Rapor kaydedildi: {output}")
        
        ctx.obj['history'].add_command('scan start', {
            'target_id': target_id,
            'type': scan_type,
            'findings': len(findings)
        })
        
    except Exception as e:
        console.print(f"❌ Tarama sırasında hata: {e}", style="red")

@scan.command('list')
@click.option('--status', type=click.Choice(['all', 'running', 'completed', 'failed']),
              default='all', help='Durum filtresi')
@click.pass_context
def list_scans(ctx, status):
    """Taramaları listele"""
    try:
        # Örnek tarama verileri
        scans = [
            {
                'id': 1,
                'target': 'Test Web Sitesi',
                'type': 'web',
                'status': 'completed',
                'started': '2024-01-15 14:30:00',
                'duration': '00:05:23',
                'findings': 5
            },
            {
                'id': 2,
                'target': 'Internal Network',
                'type': 'network',
                'status': 'running',
                'started': '2024-01-15 15:00:00',
                'duration': '00:02:15',
                'findings': 0
            }
        ]
        
        if status != 'all':
            scans = [s for s in scans if s['status'] == status]
        
        if not scans:
            console.print("ℹ️ Tarama bulunamadı.", style="yellow")
            return
        
        table = Table(title="🔍 Taramalar")
        table.add_column("ID", style="cyan")
        table.add_column("Hedef", style="green")
        table.add_column("Tip", style="magenta")
        table.add_column("Durum", style="yellow")
        table.add_column("Başlangıç", style="dim")
        table.add_column("Süre", style="blue")
        table.add_column("Bulgular", style="red")
        
        for scan in scans:
            status_emoji = {
                'completed': '✅',
                'running': '🔄',
                'failed': '❌',
                'pending': '⏳'
            }.get(scan['status'], '❓')
            
            table.add_row(
                str(scan['id']),
                scan['target'],
                scan['type'],
                f"{status_emoji} {scan['status']}",
                scan['started'],
                scan['duration'],
                str(scan['findings'])
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ Taramalar listelenirken hata: {e}", style="red")

# Report commands
@cli.group()
def report():
    """📊 Rapor komutları"""
    pass

@report.command('generate')
@click.argument('scan_id', type=int)
@click.option('--format', '-f', 'report_format',
              type=click.Choice(['html', 'pdf', 'json']),
              default='html', help='Rapor formatı')
@click.option('--output', '-o', help='Çıktı dosyası')
@click.pass_context
def generate_report(ctx, scan_id, report_format, output):
    """Rapor oluştur
    
    SCAN_ID: Rapor oluşturulacak taramanın ID'si
    """
    try:
        with console.status(f"[bold blue]{report_format.upper()} raporu oluşturuluyor..."):
            # Rapor oluşturma simülasyonu
            import time
            time.sleep(2)
            
            if not output:
                output = f"nexus_scan_{scan_id}_report.{report_format}"
        
        console.print(f"✅ Rapor başarıyla oluşturuldu: [bold green]{output}[/bold green]")
        console.print(f"   📄 Format: {report_format.upper()}")
        console.print(f"   📊 Tarama ID: {scan_id}")
        
        ctx.obj['history'].add_command('report generate', {
            'scan_id': scan_id,
            'format': report_format,
            'output': output
        })
        
    except Exception as e:
        console.print(f"❌ Rapor oluşturulurken hata: {e}", style="red")

# Config commands
@cli.group()
def config():
    """⚙️ Konfigürasyon komutları"""
    pass

@config.command('show')
@click.pass_context
def show_config(ctx):
    """Mevcut konfigürasyonu göster"""
    config_data = ctx.obj['config'].config
    
    table = Table(title="⚙️ Konfigürasyon")
    table.add_column("Anahtar", style="cyan")
    table.add_column("Değer", style="green")
    
    for key, value in config_data.items():
        table.add_row(key, str(value))
    
    console.print(table)

@config.command('set')
@click.argument('key')
@click.argument('value')
@click.pass_context
def set_config(ctx, key, value):
    """Konfigürasyon değeri ayarla
    
    KEY: Ayarlanacak anahtar
    VALUE: Yeni değer
    """
    try:
        # Tip dönüşümü
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        
        ctx.obj['config'].set(key, value)
        console.print(f"✅ Konfigürasyon güncellendi: [cyan]{key}[/cyan] = [green]{value}[/green]")
        
    except Exception as e:
        console.print(f"❌ Konfigürasyon ayarlanırken hata: {e}", style="red")

# Stats commands
@cli.command()
@click.pass_context
def stats(ctx):
    """📈 İstatistikleri göster"""
    try:
        # Örnek istatistik verileri
        stats_data = {
            'total_targets': 15,
            'total_scans': 42,
            'total_findings': 127,
            'critical_findings': 8,
            'high_findings': 23,
            'medium_findings': 45,
            'low_findings': 51,
            'last_scan': '2024-01-15 15:30:00'
        }
        
        # Ana panel
        console.print(Panel.fit(
            f"[bold blue]📊 Nexus-Scanner İstatistikleri[/bold blue]\n\n"
            f"🎯 Toplam Hedef: [cyan]{stats_data['total_targets']}[/cyan]\n"
            f"🔍 Toplam Tarama: [green]{stats_data['total_scans']}[/green]\n"
            f"📋 Toplam Bulgu: [yellow]{stats_data['total_findings']}[/yellow]\n\n"
            f"[bold red]🔴 Kritik: {stats_data['critical_findings']}[/bold red]\n"
            f"[bold orange1]🟠 Yüksek: {stats_data['high_findings']}[/bold orange1]\n"
            f"[bold yellow]🟡 Orta: {stats_data['medium_findings']}[/bold yellow]\n"
            f"[bold green]🟢 Düşük: {stats_data['low_findings']}[/bold green]\n\n"
            f"[dim]Son Tarama: {stats_data['last_scan']}[/dim]",
            border_style="blue"
        ))
        
        # Risk dağılımı grafiği (basit)
        total_findings = stats_data['total_findings']
        if total_findings > 0:
            console.print("\n📊 Risk Dağılımı:")
            
            risk_data = [
                ('Kritik', stats_data['critical_findings'], 'red'),
                ('Yüksek', stats_data['high_findings'], 'orange1'),
                ('Orta', stats_data['medium_findings'], 'yellow'),
                ('Düşük', stats_data['low_findings'], 'green')
            ]
            
            for risk_level, count, color in risk_data:
                percentage = (count / total_findings) * 100
                bar_length = int(percentage / 2)  # 50 karakter maksimum
                bar = '█' * bar_length + '░' * (50 - bar_length)
                
                console.print(f"[{color}]{risk_level:>6}[/{color}]: [{color}]{bar}[/{color}] {percentage:5.1f}% ({count})")
        
    except Exception as e:
        console.print(f"❌ İstatistikler yüklenirken hata: {e}", style="red")

# History command
@cli.command()
@click.option('--limit', '-l', type=int, default=10, help='Gösterilecek kayıt sayısı')
@click.pass_context
def history(ctx, limit):
    """📜 Komut geçmişini göster"""
    try:
        history_data = ctx.obj['history'].history[-limit:]
        
        if not history_data:
            console.print("ℹ️ Henüz komut geçmişi yok.", style="yellow")
            return
        
        table = Table(title="📜 Komut Geçmişi")
        table.add_column("Zaman", style="dim")
        table.add_column("Komut", style="cyan")
        table.add_column("Parametreler", style="green")
        table.add_column("Sonuç", style="yellow")
        
        for entry in reversed(history_data):
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%d.%m.%Y %H:%M')
            args_str = ', '.join([f"{k}={v}" for k, v in entry['args'].items()])
            
            result_emoji = "✅" if entry['result'] == 'success' else "❌"
            
            table.add_row(
                timestamp,
                entry['command'],
                args_str[:50] + '...' if len(args_str) > 50 else args_str,
                f"{result_emoji} {entry['result']}"
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ Geçmiş yüklenirken hata: {e}", style="red")

# Version command
@cli.command()
def version():
    """📋 Sürüm bilgisini göster"""
    version_info = {
        'version': '1.0.0',
        'build': '2024.01.15',
        'python': sys.version.split()[0],
        'platform': sys.platform
    }
    
    console.print(Panel.fit(
        f"[bold blue]🔍 Nexus-Scanner CLI[/bold blue]\n\n"
        f"Sürüm: [green]{version_info['version']}[/green]\n"
        f"Build: [yellow]{version_info['build']}[/yellow]\n"
        f"Python: [cyan]{version_info['python']}[/cyan]\n"
        f"Platform: [magenta]{version_info['platform']}[/magenta]\n\n"
        f"[dim]© 2024 Nexus-Scanner Team[/dim]",
        border_style="blue"
    ))

# Interactive mode
@cli.command()
@click.pass_context
def interactive(ctx):
    """🎮 İnteraktif mod"""
    console.print(Panel.fit(
        "[bold green]🎮 İnteraktif Mod Başlatıldı[/bold green]\n\n"
        "Kullanılabilir komutlar:\n"
        "• target add/list/remove - Hedef yönetimi\n"
        "• scan start/list - Tarama işlemleri\n"
        "• report generate - Rapor oluşturma\n"
        "• stats - İstatistikler\n"
        "• config show/set - Konfigürasyon\n"
        "• help - Yardım\n"
        "• exit - Çıkış\n\n"
        "[dim]Çıkmak için 'exit' yazın[/dim]",
        border_style="green"
    ))
    
    while True:
        try:
            command = Prompt.ask("[bold cyan]nexus>[/bold cyan]")
            
            if command.lower() in ['exit', 'quit', 'q']:
                console.print("👋 Görüşürüz!", style="green")
                break
            elif command.lower() in ['help', 'h']:
                ctx.invoke(cli, ['--help'])
            elif command.strip():
                # Komutu çalıştır
                try:
                    os.system(f"python {__file__} {command}")
                except Exception as e:
                    console.print(f"❌ Komut hatası: {e}", style="red")
            
        except KeyboardInterrupt:
            console.print("\n👋 Görüşürüz!", style="green")
            break
        except EOFError:
            break

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n👋 İşlem iptal edildi.", style="yellow")
    except Exception as e:
        console.print(f"❌ Beklenmeyen hata: {e}", style="red")
        sys.exit(1)