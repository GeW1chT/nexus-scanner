#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Database Manager
Profesyonel siber güvenlik aracı - Veritabanı yönetimi

Bu modül veritabanı bağlantılarını ve session'ları yönetir.
"""

import os
import logging
from contextlib import contextmanager
from typing import Generator, Optional, Dict, Any, List
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta

from .models import Base, Target, Scan, Finding, Report, User, SystemConfig
from .models import ScanType, ScanStatus, RiskLevel, VulnerabilityType

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Veritabanı yönetim sınıfı"""
    
    def __init__(self, database_url: str = None, echo: bool = False):
        """
        Veritabanı yöneticisini başlatır
        
        Args:
            database_url: Veritabanı bağlantı URL'i
            echo: SQL sorgularını logla
        """
        
        # Varsayılan SQLite veritabanı
        if database_url is None:
            db_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
            os.makedirs(db_dir, exist_ok=True)
            database_url = f"sqlite:///{os.path.join(db_dir, 'nexus_scanner.db')}"
        
        self.database_url = database_url
        self.echo = echo
        
        # Engine oluştur
        if database_url.startswith('sqlite'):
            # SQLite için özel ayarlar
            self.engine = create_engine(
                database_url,
                echo=echo,
                poolclass=StaticPool,
                connect_args={
                    'check_same_thread': False,
                    'timeout': 30
                }
            )
        else:
            # PostgreSQL, MySQL vb. için
            self.engine = create_engine(
                database_url,
                echo=echo,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True
            )
        
        # Session factory oluştur
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        logger.info(f"✅ Veritabanı bağlantısı kuruldu: {database_url.split('://')[0]}")
    
    def create_tables(self) -> bool:
        """Tüm tabloları oluşturur"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("✅ Veritabanı tabloları oluşturuldu")
            
            # Varsayılan verileri ekle
            self._insert_default_data()
            
            return True
        except Exception as e:
            logger.error(f"❌ Tablo oluşturma hatası: {str(e)}")
            return False
    
    def drop_tables(self) -> bool:
        """Tüm tabloları siler"""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.info("❌ Veritabanı tabloları silindi")
            return True
        except Exception as e:
            logger.error(f"❌ Tablo silme hatası: {str(e)}")
            return False
    
    def reset_database(self) -> bool:
        """Veritabanını sıfırlar (tüm tabloları siler ve yeniden oluşturur)"""
        logger.info("🔄 Veritabanı sıfırlanıyor...")
        
        if self.drop_tables() and self.create_tables():
            logger.info("✅ Veritabanı başarıyla sıfırlandı")
            return True
        else:
            logger.error("❌ Veritabanı sıfırlama başarısız")
            return False
    
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Context manager ile session yönetimi"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"❌ Veritabanı hatası: {str(e)}")
            raise
        finally:
            session.close()
    
    def get_db_session(self) -> Session:
        """Yeni bir session döndürür (manuel yönetim için)"""
        return self.SessionLocal()
    
    def test_connection(self) -> bool:
        """Veritabanı bağlantısını test eder"""
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            logger.info("✅ Veritabanı bağlantısı başarılı")
            return True
        except Exception as e:
            logger.error(f"❌ Veritabanı bağlantı hatası: {str(e)}")
            return False
    
    def get_database_info(self) -> Dict[str, Any]:
        """Veritabanı bilgilerini döndürür"""
        try:
            inspector = inspect(self.engine)
            tables = inspector.get_table_names()
            
            table_info = {}
            total_records = 0
            
            with self.get_session() as session:
                for table_name in tables:
                    try:
                        # Tablo kayıt sayısını al
                        result = session.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
                        count = result.scalar()
                        table_info[table_name] = count
                        total_records += count
                    except Exception:
                        table_info[table_name] = 0
            
            return {
                "database_url": self.database_url.split('://')[0] + "://...",
                "total_tables": len(tables),
                "total_records": total_records,
                "tables": table_info,
                "engine_info": {
                    "pool_size": getattr(self.engine.pool, 'size', 'N/A'),
                    "checked_out": getattr(self.engine.pool, 'checkedout', 'N/A'),
                    "overflow": getattr(self.engine.pool, 'overflow', 'N/A')
                }
            }
        except Exception as e:
            logger.error(f"❌ Veritabanı bilgi alma hatası: {str(e)}")
            return {}
    
    def _insert_default_data(self):
        """Varsayılan verileri ekler"""
        try:
            with self.get_session() as session:
                # Varsayılan sistem konfigürasyonları
                default_configs = [
                    {
                        "key": "app_name",
                        "value": "Nexus-Scanner",
                        "description": "Uygulama adı"
                    },
                    {
                        "key": "app_version",
                        "value": "1.0.0",
                        "description": "Uygulama versiyonu"
                    },
                    {
                        "key": "max_concurrent_scans",
                        "value": "5",
                        "data_type": "integer",
                        "description": "Maksimum eşzamanlı tarama sayısı"
                    },
                    {
                        "key": "default_scan_timeout",
                        "value": "3600",
                        "data_type": "integer",
                        "description": "Varsayılan tarama timeout (saniye)"
                    },
                    {
                        "key": "report_retention_days",
                        "value": "90",
                        "data_type": "integer",
                        "description": "Rapor saklama süresi (gün)"
                    },
                    {
                        "key": "enable_notifications",
                        "value": "true",
                        "data_type": "boolean",
                        "description": "Bildirimleri etkinleştir"
                    }
                ]
                
                for config_data in default_configs:
                    # Zaten var mı kontrol et
                    existing = session.query(SystemConfig).filter_by(key=config_data["key"]).first()
                    if not existing:
                        config = SystemConfig(**config_data)
                        session.add(config)
                
                session.commit()
                logger.info("✅ Varsayılan konfigürasyon verileri eklendi")
                
        except Exception as e:
            logger.error(f"❌ Varsayılan veri ekleme hatası: {str(e)}")
    
    def backup_database(self, backup_path: str = None) -> bool:
        """Veritabanını yedekler (SQLite için)"""
        if not self.database_url.startswith('sqlite'):
            logger.warning("⚠️ Backup sadece SQLite veritabanları için desteklenir")
            return False
        
        try:
            import shutil
            
            # Kaynak dosya yolu
            source_path = self.database_url.replace('sqlite:///', '')
            
            # Hedef dosya yolu
            if backup_path is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"{source_path}.backup_{timestamp}"
            
            # Dosyayı kopyala
            shutil.copy2(source_path, backup_path)
            
            logger.info(f"✅ Veritabanı yedeklendi: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Veritabanı yedekleme hatası: {str(e)}")
            return False
    
    def cleanup_old_data(self, days: int = 90) -> Dict[str, int]:
        """Eski verileri temizler"""
        cleanup_stats = {
            "deleted_scans": 0,
            "deleted_findings": 0,
            "deleted_reports": 0
        }
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            with self.get_session() as session:
                # Eski taramaları sil (cascade ile findings ve reports da silinir)
                old_scans = session.query(Scan).filter(
                    Scan.created_at < cutoff_date,
                    Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED])
                ).all()
                
                for scan in old_scans:
                    cleanup_stats["deleted_findings"] += len(scan.findings)
                    cleanup_stats["deleted_reports"] += len(scan.reports)
                    session.delete(scan)
                    cleanup_stats["deleted_scans"] += 1
                
                session.commit()
                
            logger.info(f"✅ {days} günden eski veriler temizlendi: {cleanup_stats}")
            
        except Exception as e:
            logger.error(f"❌ Veri temizleme hatası: {str(e)}")
        
        return cleanup_stats
    
    def get_statistics(self) -> Dict[str, Any]:
        """Veritabanı istatistiklerini döndürür"""
        stats = {
            "targets": {"total": 0, "active": 0},
            "scans": {"total": 0, "completed": 0, "running": 0, "failed": 0},
            "findings": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "reports": {"total": 0, "html": 0, "pdf": 0, "json": 0},
            "users": {"total": 0, "active": 0}
        }
        
        try:
            with self.get_session() as session:
                # Target istatistikleri
                stats["targets"]["total"] = session.query(Target).count()
                stats["targets"]["active"] = session.query(Target).filter_by(is_active=True).count()
                
                # Scan istatistikleri
                stats["scans"]["total"] = session.query(Scan).count()
                stats["scans"]["completed"] = session.query(Scan).filter_by(status=ScanStatus.COMPLETED).count()
                stats["scans"]["running"] = session.query(Scan).filter_by(status=ScanStatus.RUNNING).count()
                stats["scans"]["failed"] = session.query(Scan).filter_by(status=ScanStatus.FAILED).count()
                
                # Finding istatistikleri
                stats["findings"]["total"] = session.query(Finding).count()
                stats["findings"]["critical"] = session.query(Finding).filter_by(risk_level=RiskLevel.CRITICAL).count()
                stats["findings"]["high"] = session.query(Finding).filter_by(risk_level=RiskLevel.HIGH).count()
                stats["findings"]["medium"] = session.query(Finding).filter_by(risk_level=RiskLevel.MEDIUM).count()
                stats["findings"]["low"] = session.query(Finding).filter_by(risk_level=RiskLevel.LOW).count()
                
                # Report istatistikleri
                stats["reports"]["total"] = session.query(Report).count()
                stats["reports"]["html"] = session.query(Report).filter_by(format="html").count()
                stats["reports"]["pdf"] = session.query(Report).filter_by(format="pdf").count()
                stats["reports"]["json"] = session.query(Report).filter_by(format="json").count()
                
                # User istatistikleri
                stats["users"]["total"] = session.query(User).count()
                stats["users"]["active"] = session.query(User).filter_by(is_active=True).count()
                
        except Exception as e:
            logger.error(f"❌ İstatistik alma hatası: {str(e)}")
        
        return stats
    
    def close(self):
        """Veritabanı bağlantısını kapatır"""
        try:
            self.engine.dispose()
            logger.info("✅ Veritabanı bağlantısı kapatıldı")
        except Exception as e:
            logger.error(f"❌ Bağlantı kapatma hatası: {str(e)}")

# Global database manager instance
_db_manager: Optional[DatabaseManager] = None

def get_database_manager(database_url: str = None, echo: bool = False) -> DatabaseManager:
    """Global database manager instance'ını döndürür"""
    global _db_manager
    
    if _db_manager is None:
        _db_manager = DatabaseManager(database_url, echo)
    
    return _db_manager

def init_database(database_url: str = None, echo: bool = False, reset: bool = False) -> bool:
    """Veritabanını başlatır"""
    try:
        db_manager = get_database_manager(database_url, echo)
        
        # Bağlantıyı test et
        if not db_manager.test_connection():
            return False
        
        # Reset isteniyorsa veritabanını sıfırla
        if reset:
            return db_manager.reset_database()
        else:
            return db_manager.create_tables()
            
    except Exception as e:
        logger.error(f"❌ Veritabanı başlatma hatası: {str(e)}")
        return False

# Context manager for database sessions
@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Global database session context manager"""
    db_manager = get_database_manager()
    with db_manager.get_session() as session:
        yield session

# Test fonksiyonu
if __name__ == "__main__":
    print("Nexus-Scanner Database Manager Test")
    print("=" * 40)
    
    # Test veritabanı oluştur
    db_manager = DatabaseManager(echo=True)
    
    # Bağlantıyı test et
    if db_manager.test_connection():
        print("✅ Veritabanı bağlantısı başarılı")
        
        # Tabloları oluştur
        if db_manager.create_tables():
            print("✅ Tablolar oluşturuldu")
            
            # Veritabanı bilgilerini göster
            info = db_manager.get_database_info()
            print(f"\n📊 Veritabanı Bilgileri:")
            print(f"Toplam Tablo: {info.get('total_tables', 0)}")
            print(f"Toplam Kayıt: {info.get('total_records', 0)}")
            
            # İstatistikleri göster
            stats = db_manager.get_statistics()
            print(f"\n📈 İstatistikler:")
            for category, data in stats.items():
                if isinstance(data, dict):
                    total = data.get('total', 0)
                    print(f"{category.title()}: {total}")
        
        # Bağlantıyı kapat
        db_manager.close()
    else:
        print("❌ Veritabanı bağlantısı başarısız")