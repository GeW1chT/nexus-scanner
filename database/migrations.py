#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Database Migrations
Profesyonel siber güvenlik aracı - Veritabanı migration sistemi

Bu modül veritabanı şema değişikliklerini yönetir.
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import text, inspect
from sqlalchemy.exc import SQLAlchemyError

from .database import get_database_manager, get_db_session
from .models import Base

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Migration:
    """Tek bir migration'ı temsil eden sınıf"""
    
    def __init__(self, version: str, name: str, description: str = ""):
        self.version = version
        self.name = name
        self.description = description
        self.timestamp = datetime.now()
        self.up_queries: List[str] = []
        self.down_queries: List[str] = []
    
    def add_up_query(self, query: str):
        """Migration için SQL sorgusu ekler"""
        self.up_queries.append(query)
    
    def add_down_query(self, query: str):
        """Rollback için SQL sorgusu ekler"""
        self.down_queries.append(query)
    
    def to_dict(self) -> Dict[str, Any]:
        """Migration'ı dictionary'ye çevirir"""
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "up_queries": self.up_queries,
            "down_queries": self.down_queries
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Migration':
        """Dictionary'den Migration oluşturur"""
        migration = cls(data["version"], data["name"], data.get("description", ""))
        migration.timestamp = datetime.fromisoformat(data["timestamp"])
        migration.up_queries = data.get("up_queries", [])
        migration.down_queries = data.get("down_queries", [])
        return migration

class MigrationManager:
    """Migration yönetim sınıfı"""
    
    def __init__(self, migrations_dir: str = None):
        """
        Migration manager'ı başlatır
        
        Args:
            migrations_dir: Migration dosyalarının bulunduğu dizin
        """
        if migrations_dir is None:
            migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
        
        self.migrations_dir = migrations_dir
        os.makedirs(self.migrations_dir, exist_ok=True)
        
        self.db_manager = get_database_manager()
        self._ensure_migration_table()
    
    def _ensure_migration_table(self):
        """Migration tablosunun var olduğundan emin olur"""
        try:
            with get_db_session() as session:
                # Migration tablosunu oluştur
                create_table_query = """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version VARCHAR(50) NOT NULL UNIQUE,
                    name VARCHAR(200) NOT NULL,
                    description TEXT,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    execution_time_ms INTEGER DEFAULT 0
                )
                """
                
                session.execute(text(create_table_query))
                session.commit()
                
        except Exception as e:
            logger.error(f"❌ Migration tablosu oluşturma hatası: {str(e)}")
    
    def create_migration(self, name: str, description: str = "") -> Migration:
        """Yeni bir migration oluşturur"""
        # Version oluştur (timestamp bazlı)
        version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        migration = Migration(version, name, description)
        
        # Migration dosyasını kaydet
        self._save_migration(migration)
        
        logger.info(f"✅ Migration oluşturuldu: {version}_{name}")
        return migration
    
    def _save_migration(self, migration: Migration):
        """Migration'ı dosyaya kaydeder"""
        filename = f"{migration.version}_{migration.name.replace(' ', '_').lower()}.json"
        filepath = os.path.join(self.migrations_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(migration.to_dict(), f, indent=2, ensure_ascii=False)
    
    def load_migrations(self) -> List[Migration]:
        """Tüm migration'ları yükler"""
        migrations = []
        
        if not os.path.exists(self.migrations_dir):
            return migrations
        
        for filename in sorted(os.listdir(self.migrations_dir)):
            if filename.endswith('.json'):
                filepath = os.path.join(self.migrations_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        migration = Migration.from_dict(data)
                        migrations.append(migration)
                except Exception as e:
                    logger.error(f"❌ Migration yükleme hatası ({filename}): {str(e)}")
        
        return migrations
    
    def get_applied_migrations(self) -> List[str]:
        """Uygulanmış migration'ların listesini döndürür"""
        try:
            with get_db_session() as session:
                result = session.execute(text("SELECT version FROM schema_migrations ORDER BY version"))
                return [row[0] for row in result.fetchall()]
        except Exception as e:
            logger.error(f"❌ Uygulanmış migration'ları alma hatası: {str(e)}")
            return []
    
    def get_pending_migrations(self) -> List[Migration]:
        """Bekleyen migration'ları döndürür"""
        all_migrations = self.load_migrations()
        applied_versions = set(self.get_applied_migrations())
        
        return [m for m in all_migrations if m.version not in applied_versions]
    
    def apply_migration(self, migration: Migration) -> bool:
        """Tek bir migration'ı uygular"""
        logger.info(f"🔄 Migration uygulanıyor: {migration.version}_{migration.name}")
        
        start_time = datetime.now()
        
        try:
            with get_db_session() as session:
                # Migration sorgularını çalıştır
                for query in migration.up_queries:
                    if query.strip():
                        session.execute(text(query))
                
                # Migration kaydını ekle
                execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
                
                insert_query = text("""
                    INSERT INTO schema_migrations (version, name, description, execution_time_ms)
                    VALUES (:version, :name, :description, :execution_time)
                """)
                
                session.execute(insert_query, {
                    "version": migration.version,
                    "name": migration.name,
                    "description": migration.description,
                    "execution_time": execution_time
                })
                
                session.commit()
                
            logger.info(f"✅ Migration başarıyla uygulandı: {migration.version} ({execution_time}ms)")
            return True
            
        except Exception as e:
            logger.error(f"❌ Migration uygulama hatası: {str(e)}")
            return False
    
    def rollback_migration(self, migration: Migration) -> bool:
        """Tek bir migration'ı geri alır"""
        logger.info(f"🔄 Migration geri alınıyor: {migration.version}_{migration.name}")
        
        try:
            with get_db_session() as session:
                # Rollback sorgularını çalıştır
                for query in reversed(migration.down_queries):
                    if query.strip():
                        session.execute(text(query))
                
                # Migration kaydını sil
                delete_query = text("DELETE FROM schema_migrations WHERE version = :version")
                session.execute(delete_query, {"version": migration.version})
                
                session.commit()
                
            logger.info(f"✅ Migration başarıyla geri alındı: {migration.version}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Migration rollback hatası: {str(e)}")
            return False
    
    def migrate_up(self, target_version: str = None) -> bool:
        """Bekleyen migration'ları uygular"""
        pending_migrations = self.get_pending_migrations()
        
        if not pending_migrations:
            logger.info("✅ Uygulanacak migration yok")
            return True
        
        # Hedef version belirtilmişse filtrele
        if target_version:
            pending_migrations = [m for m in pending_migrations if m.version <= target_version]
        
        logger.info(f"🔄 {len(pending_migrations)} migration uygulanacak")
        
        success_count = 0
        for migration in pending_migrations:
            if self.apply_migration(migration):
                success_count += 1
            else:
                logger.error(f"❌ Migration durdu: {migration.version}")
                break
        
        logger.info(f"✅ {success_count}/{len(pending_migrations)} migration başarıyla uygulandı")
        return success_count == len(pending_migrations)
    
    def migrate_down(self, target_version: str = None, steps: int = 1) -> bool:
        """Migration'ları geri alır"""
        applied_versions = self.get_applied_migrations()
        all_migrations = {m.version: m for m in self.load_migrations()}
        
        # Geri alınacak migration'ları belirle
        if target_version:
            # Belirli bir versiyona kadar geri al
            to_rollback = [v for v in reversed(applied_versions) if v > target_version]
        else:
            # Belirli sayıda adım geri al
            to_rollback = list(reversed(applied_versions))[:steps]
        
        if not to_rollback:
            logger.info("✅ Geri alınacak migration yok")
            return True
        
        logger.info(f"🔄 {len(to_rollback)} migration geri alınacak")
        
        success_count = 0
        for version in to_rollback:
            if version in all_migrations:
                migration = all_migrations[version]
                if self.rollback_migration(migration):
                    success_count += 1
                else:
                    logger.error(f"❌ Rollback durdu: {version}")
                    break
            else:
                logger.warning(f"⚠️ Migration dosyası bulunamadı: {version}")
        
        logger.info(f"✅ {success_count}/{len(to_rollback)} migration başarıyla geri alındı")
        return success_count == len(to_rollback)
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Migration durumunu döndürür"""
        all_migrations = self.load_migrations()
        applied_versions = set(self.get_applied_migrations())
        
        applied = [m for m in all_migrations if m.version in applied_versions]
        pending = [m for m in all_migrations if m.version not in applied_versions]
        
        return {
            "total_migrations": len(all_migrations),
            "applied_count": len(applied),
            "pending_count": len(pending),
            "applied_migrations": [{
                "version": m.version,
                "name": m.name,
                "description": m.description
            } for m in applied],
            "pending_migrations": [{
                "version": m.version,
                "name": m.name,
                "description": m.description
            } for m in pending]
        }
    
    def reset_migrations(self) -> bool:
        """Tüm migration'ları sıfırlar"""
        try:
            with get_db_session() as session:
                session.execute(text("DELETE FROM schema_migrations"))
                session.commit()
            
            logger.info("✅ Tüm migration kayıtları silindi")
            return True
            
        except Exception as e:
            logger.error(f"❌ Migration sıfırlama hatası: {str(e)}")
            return False

# Önceden tanımlanmış migration'lar
def create_initial_migrations():
    """İlk migration'ları oluşturur"""
    manager = MigrationManager()
    
    # İlk migration: Temel tablolar
    initial_migration = manager.create_migration(
        "initial_tables",
        "Temel veritabanı tablolarını oluşturur"
    )
    
    # Tablo oluşturma sorguları (SQLite için)
    table_queries = [
        """
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(200) NOT NULL,
            url VARCHAR(500),
            ip_address VARCHAR(45),
            description TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            scan_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            duration_seconds INTEGER,
            total_findings INTEGER DEFAULT 0,
            critical_findings INTEGER DEFAULT 0,
            high_findings INTEGER DEFAULT 0,
            medium_findings INTEGER DEFAULT 0,
            low_findings INTEGER DEFAULT 0,
            info_findings INTEGER DEFAULT 0,
            scan_config TEXT,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            vulnerability_type VARCHAR(100) NOT NULL,
            title VARCHAR(500) NOT NULL,
            description TEXT,
            risk_level VARCHAR(20) NOT NULL,
            confidence VARCHAR(20) DEFAULT 'medium',
            severity_score REAL DEFAULT 0.0,
            affected_url VARCHAR(1000),
            affected_parameter VARCHAR(200),
            payload TEXT,
            evidence TEXT,
            recommendation TEXT,
            references TEXT,
            is_false_positive BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            format VARCHAR(20) NOT NULL,
            file_path VARCHAR(1000),
            file_size INTEGER,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(200) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(200),
            role VARCHAR(50) DEFAULT 'user',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            api_key VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS system_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key VARCHAR(100) UNIQUE NOT NULL,
            value TEXT NOT NULL,
            data_type VARCHAR(20) DEFAULT 'string',
            description TEXT,
            is_encrypted BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
    
    # Drop sorguları
    drop_queries = [
        "DROP TABLE IF EXISTS system_config",
        "DROP TABLE IF EXISTS users",
        "DROP TABLE IF EXISTS reports",
        "DROP TABLE IF EXISTS findings",
        "DROP TABLE IF EXISTS scans",
        "DROP TABLE IF EXISTS targets"
    ]
    
    # Sorguları migration'a ekle
    for query in table_queries:
        initial_migration.add_up_query(query)
    
    for query in drop_queries:
        initial_migration.add_down_query(query)
    
    # Migration'ı kaydet
    manager._save_migration(initial_migration)
    
    logger.info("✅ İlk migration'lar oluşturuldu")
    return manager

# Global migration manager
_migration_manager: Optional[MigrationManager] = None

def get_migration_manager() -> MigrationManager:
    """Global migration manager instance'ını döndürür"""
    global _migration_manager
    
    if _migration_manager is None:
        _migration_manager = MigrationManager()
    
    return _migration_manager

# Test fonksiyonu
if __name__ == "__main__":
    print("Nexus-Scanner Migration Manager Test")
    print("=" * 40)
    
    # Migration manager oluştur
    manager = MigrationManager()
    
    # İlk migration'ları oluştur
    create_initial_migrations()
    
    # Migration durumunu göster
    status = manager.get_migration_status()
    print(f"\n📊 Migration Durumu:")
    print(f"Toplam Migration: {status['total_migrations']}")
    print(f"Uygulanmış: {status['applied_count']}")
    print(f"Bekleyen: {status['pending_count']}")
    
    # Bekleyen migration'ları uygula
    if status['pending_count'] > 0:
        print(f"\n🔄 {status['pending_count']} migration uygulanıyor...")
        if manager.migrate_up():
            print("✅ Tüm migration'lar başarıyla uygulandı")
        else:
            print("❌ Migration uygulama başarısız")
    
    # Final durumu göster
    final_status = manager.get_migration_status()
    print(f"\n📊 Final Durum:")
    print(f"Uygulanmış: {final_status['applied_count']}")
    print(f"Bekleyen: {final_status['pending_count']}")