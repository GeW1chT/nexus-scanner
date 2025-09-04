# Nexus-Scanner CLI

Nexus-Scanner'ın komut satırı arayüzü (CLI) modülü. Bu modül, güvenlik taramalarını komut satırından yönetmenizi sağlar.

## 🚀 Özellikler

### Hedef Yönetimi
- Hedef ekleme/silme/listeleme
- Web, network ve API hedef türleri
- Hedef açıklamaları ve etiketleme

### Tarama İşlemleri
- Web güvenlik taramaları
- Network port taramaları
- Kapsamlı güvenlik analizi
- İlerleme takibi ve durum kontrolü

### Rapor Oluşturma
- HTML, PDF ve JSON formatları
- Detaylı güvenlik raporları
- Risk seviyesi sınıflandırması
- Çözüm önerileri

### Konfigürasyon
- Esnek ayar yönetimi
- JSON tabanlı konfigürasyon
- Komut geçmişi takibi
- Kullanıcı tercihleri

## 📦 Kurulum

### Gereksinimler
```bash
pip install -r requirements.txt
```

### Bağımlılıklar
- **click**: Komut satırı arayüzü
- **rich**: Zengin terminal çıktısı
- **typer**: Modern CLI framework
- **requests**: HTTP istekleri
- **pydantic**: Veri doğrulama
- **SQLAlchemy**: Veritabanı işlemleri

## 🎯 Kullanım

### Temel Komutlar

```bash
# CLI yardımını görüntüle
python -m cli --help

# Sürüm bilgisini göster
python -m cli version

# Konfigürasyonu göster
python -m cli config show
```

### Hedef Yönetimi

```bash
# Yeni hedef ekle
python -m cli target add "test-site" "https://example.com" --type web --description "Test sitesi"

# Hedefleri listele
python -m cli target list

# JSON formatında listele
python -m cli target list --format json

# Hedef sil
python -m cli target remove 1 --force
```

### Tarama İşlemleri

```bash
# Web taraması başlat
python -m cli scan start 1 --type web --threads 5

# Network taraması başlat
python -m cli scan start 1 --type network --timeout 30

# Kapsamlı tarama
python -m cli scan start 1 --type full

# Taramaları listele
python -m cli scan list

# Belirli durumda taramaları filtrele
python -m cli scan list --status completed
```

### Rapor Oluşturma

```bash
# HTML raporu oluştur
python -m cli report generate 1 --format html --output report.html

# PDF raporu oluştur
python -m cli report generate 1 --format pdf

# JSON raporu oluştur
python -m cli report generate 1 --format json
```

### Konfigürasyon Yönetimi

```bash
# Ayar değiştir
python -m cli config set database_url "postgresql://user:pass@localhost/nexus"

# Ayar görüntüle
python -m cli config get database_url

# Tüm ayarları göster
python -m cli config show
```

### İstatistikler ve Geçmiş

```bash
# İstatistikleri göster
python -m cli stats

# Komut geçmişini göster
python -m cli history

# Geçmişi temizle
python -m cli history clear
```

## ⚙️ Konfigürasyon

### Konfigürasyon Dosyası
Konfigürasyon dosyası `~/.nexus-scanner/config.json` konumunda saklanır:

```json
{
  "database_url": "postgresql://localhost/nexus_scanner",
  "api_base_url": "http://localhost:8000",
  "reports_dir": "./reports",
  "timeout": 30,
  "max_threads": 10,
  "debug": false,
  "output_format": "table",
  "auto_save": true
}
```

### Ortam Değişkenleri
```bash
export NEXUS_CONFIG_DIR="/path/to/config"
export NEXUS_DATABASE_URL="postgresql://localhost/nexus"
export NEXUS_API_URL="http://localhost:8000"
export NEXUS_DEBUG="true"
```

## 📊 Çıktı Formatları

### Tablo Formatı (Varsayılan)
```
┌────┬─────────────┬─────────────────────┬──────────┬─────────────┐
│ ID │ İsim        │ URL                 │ Tür      │ Durum       │
├────┼─────────────┼─────────────────────┼──────────┼─────────────┤
│ 1  │ test-site   │ https://example.com │ web      │ aktif       │
└────┴─────────────┴─────────────────────┴──────────┴─────────────┘
```

### JSON Formatı
```json
{
  "targets": [
    {
      "id": 1,
      "name": "test-site",
      "url": "https://example.com",
      "type": "web",
      "status": "active",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### CSV Formatı
```csv
id,name,url,type,status,created_at
1,test-site,https://example.com,web,active,2024-01-15T10:30:00Z
```

## 🔧 Gelişmiş Kullanım

### Batch İşlemler
```bash
# Dosyadan hedefler ekle
cat targets.txt | xargs -I {} python -m cli target add {} {} --type web

# Toplu tarama başlat
python -m cli scan start --all --type web
```

### Pipeline Entegrasyonu
```bash
# CI/CD pipeline için
python -m cli scan start 1 --format json | jq '.status'

# Otomatik rapor oluşturma
python -m cli report generate --all --format pdf --output-dir ./reports/
```

### Scripting
```python
#!/usr/bin/env python3
from cli import NexusCLI, run_cli

# Programatik kullanım
cli_app = NexusCLI()
result = cli_app.add_target("test", "https://example.com")
print(f"Hedef eklendi: {result}")

# Komut çalıştırma
exit_code = run_cli(['target', 'list', '--format', 'json'])
```

## 🧪 Test Etme

### Unit Testler
```bash
# Tüm testleri çalıştır
python -m pytest cli/test_cli.py -v

# Belirli test sınıfını çalıştır
python -m pytest cli/test_cli.py::TestCLICommands -v

# Coverage ile
python -m pytest cli/test_cli.py --cov=cli --cov-report=html
```

### Integration Testler
```bash
# Entegrasyon testleri
python -m pytest cli/test_cli.py -m integration

# Performans testleri
python -m pytest cli/test_cli.py -m slow
```

## 📝 Örnekler

### Örnek 1: Web Sitesi Güvenlik Taraması
```bash
# 1. Hedef ekle
python -m cli target add "company-website" "https://company.com" --type web

# 2. Tarama başlat
python -m cli scan start 1 --type web --threads 5

# 3. Sonuçları kontrol et
python -m cli scan list --status completed

# 4. Rapor oluştur
python -m cli report generate 1 --format html --output security-report.html
```

### Örnek 2: Network Altyapı Taraması
```bash
# 1. Network hedefi ekle
python -m cli target add "internal-network" "192.168.1.0/24" --type network

# 2. Port taraması başlat
python -m cli scan start 2 --type network --timeout 60

# 3. PDF raporu oluştur
python -m cli report generate 2 --format pdf
```

### Örnek 3: API Güvenlik Testi
```bash
# 1. API hedefi ekle
python -m cli target add "api-server" "https://api.company.com" --type api

# 2. API taraması başlat
python -m cli scan start 3 --type api

# 3. JSON raporu al
python -m cli report generate 3 --format json --output api-security.json
```

## 🔍 Sorun Giderme

### Yaygın Sorunlar

**Bağlantı Hatası:**
```bash
# Veritabanı bağlantısını kontrol et
python -m cli config get database_url

# API sunucusunu kontrol et
curl http://localhost:8000/health
```

**Yetki Hatası:**
```bash
# Konfigürasyon dizini yetkilerini kontrol et
ls -la ~/.nexus-scanner/

# Gerekirse yetkileri düzelt
chmod 755 ~/.nexus-scanner/
```

**Performans Sorunları:**
```bash
# Thread sayısını azalt
python -m cli config set max_threads 3

# Timeout süresini artır
python -m cli config set timeout 60
```

### Debug Modu
```bash
# Debug modunu etkinleştir
python -m cli config set debug true

# Verbose çıktı ile çalıştır
python -m cli --verbose target list
```

## 📚 API Referansı

### CLIConfig Sınıfı
```python
class CLIConfig:
    def __init__(self, config_path=None)
    def load_config(self) -> dict
    def save_config(self, config: dict)
    def get(self, key: str, default=None)
    def set(self, key: str, value)
```

### CLIHistory Sınıfı
```python
class CLIHistory:
    def __init__(self, config: CLIConfig)
    def add_command(self, command: str, args: dict, result: str)
    def get_history(self, limit: int = 50) -> list
    def clear_history()
```

### NexusCLI Sınıfı
```python
class NexusCLI:
    def __init__(self, config_path=None)
    def get_config(self) -> dict
    def get_history(self) -> list
    def add_target(self, name: str, url: str, **kwargs) -> dict
    def start_scan(self, target_id: int, **kwargs) -> dict
```

## 🤝 Katkıda Bulunma

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

### Geliştirme Ortamı
```bash
# Development dependencies
pip install -r requirements-dev.txt

# Pre-commit hooks
pre-commit install

# Code formatting
black cli/
flake8 cli/
mypy cli/
```

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](../LICENSE) dosyasına bakın.

## 🆘 Destek

- **Dokümantasyon**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/nexus-scanner/nexus-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/nexus-scanner/nexus-scanner/discussions)
- **Email**: support@nexus-scanner.com

## 🔄 Sürüm Geçmişi

### v1.0.0 (2024-01-15)
- ✨ İlk stabil sürüm
- 🎯 Temel CLI komutları
- 📊 Rapor oluşturma
- ⚙️ Konfigürasyon yönetimi
- 🧪 Kapsamlı test coverage

### v0.9.0 (2024-01-10)
- 🚀 Beta sürüm
- 🔧 CLI framework kurulumu
- 📝 Temel komut yapısı
- 🎨 Rich terminal çıktısı

---

**Nexus-Scanner CLI** - Güvenlik taramalarınızı komut satırından yönetin! 🛡️