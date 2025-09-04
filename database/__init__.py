#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Database Package
Profesyonel siber güvenlik aracı - Veritabanı modülleri

Bu paket veritabanı işlemlerini yönetir:
- Models: Veritabanı tablolarını tanımlar
- Database: Bağlantı ve session yönetimi
- Migrations: Şema değişikliklerini yönetir
"""

# Version bilgisi
__version__ = "1.0.0"
__author__ = "Nexus-Scanner Team"
__description__ = "Professional cybersecurity tool - Database modules"

# Core imports
from .models import (
    # Base
    Base,
    
    # Models
    Target,
    Scan,
    Finding,
    Report,
    User,
    AuditLog,
    ScanTemplate,
    ScanSchedule,
    SystemConfig,
    
    # Enums
    ScanType,
    ScanStatus,
    RiskLevel,
    VulnerabilityType,
    
    # Helper functions
    create_tables,
    drop_tables,
    get_table_info
)

from .database import (
    DatabaseManager,
    get_database_manager,
    init_database,
    get_db_session
)

from .migrations import (
    Migration,
    MigrationManager,
    get_migration_manager,
    create_initial_migrations
)

# Convenience functions
def setup_database(database_url: str = None, echo: bool = False, reset: bool = False) -> bool:
    """
    Veritabanını kurulum için tek fonksiyon
    
    Args:
        database_url: Veritabanı bağlantı URL'i
        echo: SQL sorgularını logla
        reset: Veritabanını sıfırla
    
    Returns:
        bool: Kurulum başarılı mı
    """
    try:
        # Database manager'ı başlat
        db_manager = get_database_manager(database_url, echo)
        
        # Bağlantıyı test et
        if not db_manager.test_connection():
            return False
        
        # Migration manager'ı başlat
        migration_manager = get_migration_manager()
        
        # Reset isteniyorsa
        if reset:
            db_manager.reset_database()
            migration_manager.reset_migrations()
        
        # İlk migration'ları oluştur (eğer yoksa)
        create_initial_migrations()
        
        # Bekleyen migration'ları uygula
        migration_manager.migrate_up()
        
        return True
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"❌ Veritabanı kurulum hatası: {str(e)}")
        return False

def get_database_status() -> dict:
    """
    Veritabanı durumunu döndürür
    
    Returns:
        dict: Veritabanı durum bilgileri
    """
    try:
        db_manager = get_database_manager()
        migration_manager = get_migration_manager()
        
        # Database bilgileri
        db_info = db_manager.get_database_info()
        db_stats = db_manager.get_statistics()
        
        # Migration bilgileri
        migration_status = migration_manager.get_migration_status()
        
        return {
            "database": {
                "connected": db_manager.test_connection(),
                "info": db_info,
                "statistics": db_stats
            },
            "migrations": migration_status,
            "status": "healthy" if db_manager.test_connection() else "error"
        }
        
    except Exception as e:
        return {
            "database": {"connected": False},
            "migrations": {},
            "status": "error",
            "error": str(e)
        }

# Package exports
__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__description__",
    
    # Models
    "Base",
    "Target",
    "Scan",
    "Finding",
    "Report",
    "User",
    "AuditLog",
    "ScanTemplate",
    "ScanSchedule",
    "SystemConfig",
    
    # Enums
    "ScanType",
    "ScanStatus",
    "RiskLevel",
    "VulnerabilityType",
    
    # Database management
    "DatabaseManager",
    "get_database_manager",
    "init_database",
    "get_db_session",
    
    # Migration management
    "Migration",
    "MigrationManager",
    "get_migration_manager",
    "create_initial_migrations",
    
    # Helper functions
    "create_tables",
    "drop_tables",
    "get_table_info",
    "setup_database",
    "get_database_status"
]

# Logging ayarları
import logging
logger = logging.getLogger(__name__)
logger.info(f"Nexus-Scanner Database Package v{__version__} loaded")