import React, { createContext, useContext, useReducer, useEffect, useCallback, ReactNode } from 'react';
import { settingsService } from '../services/settingsService';

// Theme Types
export type ThemeMode = 'light' | 'dark' | 'system';
export type Language = 'tr' | 'en';
export type DateFormat = 'DD/MM/YYYY' | 'MM/DD/YYYY' | 'YYYY-MM-DD';
export type TimeFormat = '24h' | '12h';
export type TableDensity = 'comfortable' | 'standard' | 'compact';

// Notification Settings
interface NotificationSettings {
  scanComplete: boolean;
  scanFailed: boolean;
  newVulnerability: boolean;
  systemUpdates: boolean;
  emailNotifications: boolean;
  pushNotifications: boolean;
  soundEnabled: boolean;
}

// Dashboard Settings
interface DashboardSettings {
  autoRefresh: boolean;
  refreshInterval: number; // seconds
  showWelcomeMessage: boolean;
  defaultView: 'overview' | 'recent-scans' | 'vulnerabilities';
  chartsAnimated: boolean;
  compactMode: boolean;
}

// Scan Settings
interface ScanSettings {
  defaultTimeout: number; // seconds
  maxConcurrentScans: number;
  autoSaveReports: boolean;
  defaultReportFormat: 'html' | 'pdf' | 'json';
  includeScreenshots: boolean;
  detailedLogging: boolean;
}

// Security Settings
interface SecuritySettings {
  sessionTimeout: number; // minutes
  requirePasswordChange: boolean;
  passwordChangeInterval: number; // days
  twoFactorEnabled: boolean;
  loginNotifications: boolean;
  ipWhitelist: string[];
}

// Performance Settings
interface PerformanceSettings {
  enableCaching: boolean;
  cacheTimeout: number; // minutes
  lazyLoading: boolean;
  compressionEnabled: boolean;
  maxMemoryUsage: number; // MB
  backgroundSync: boolean;
}

// Settings State Interface
interface SettingsState {
  // Appearance
  theme: ThemeMode;
  language: Language;
  dateFormat: DateFormat;
  timeFormat: TimeFormat;
  tableDensity: TableDensity;
  fontSize: number;
  sidebarCollapsed: boolean;
  
  // Notifications
  notifications: NotificationSettings;
  
  // Dashboard
  dashboard: DashboardSettings;
  
  // Scanning
  scanning: ScanSettings;
  
  // Security
  security: SecuritySettings;
  
  // Performance
  performance: PerformanceSettings;
  
  // State management
  isLoading: boolean;
  error: string | null;
  hasUnsavedChanges: boolean;
}

// Settings Actions
type SettingsAction =
  | { type: 'SETTINGS_LOAD_START' }
  | { type: 'SETTINGS_LOAD_SUCCESS'; payload: Partial<SettingsState> }
  | { type: 'SETTINGS_LOAD_FAILURE'; payload: string }
  | { type: 'SETTINGS_UPDATE'; payload: Partial<SettingsState> }
  | { type: 'SETTINGS_SAVE_START' }
  | { type: 'SETTINGS_SAVE_SUCCESS' }
  | { type: 'SETTINGS_SAVE_FAILURE'; payload: string }
  | { type: 'SETTINGS_RESET_TO_DEFAULT' }
  | { type: 'SETTINGS_CLEAR_ERROR' }
  | { type: 'SETTINGS_SET_UNSAVED'; payload: boolean };

// Settings Context Interface
interface SettingsContextType {
  // State
  settings: SettingsState;
  isLoading: boolean;
  error: string | null;
  hasUnsavedChanges: boolean;
  
  // Actions
  updateSettings: (updates: Partial<SettingsState>) => void;
  saveSettings: () => Promise<void>;
  loadSettings: () => Promise<void>;
  resetToDefaults: () => void;
  clearError: () => void;
  
  // Convenience methods
  toggleTheme: () => void;
  setLanguage: (language: Language) => void;
  toggleSidebar: () => void;
  updateNotificationSetting: (key: keyof NotificationSettings, value: boolean) => void;
  updateDashboardSetting: (key: keyof DashboardSettings, value: any) => void;
  updateScanSetting: (key: keyof ScanSettings, value: any) => void;
  updateSecuritySetting: (key: keyof SecuritySettings, value: any) => void;
  updatePerformanceSetting: (key: keyof PerformanceSettings, value: any) => void;
}

// Default Settings
const defaultSettings: SettingsState = {
  // Appearance
  theme: 'system',
  language: 'tr',
  dateFormat: 'DD/MM/YYYY',
  timeFormat: '24h',
  tableDensity: 'standard',
  fontSize: 14,
  sidebarCollapsed: false,
  
  // Notifications
  notifications: {
    scanComplete: true,
    scanFailed: true,
    newVulnerability: true,
    systemUpdates: true,
    emailNotifications: false,
    pushNotifications: true,
    soundEnabled: true,
  },
  
  // Dashboard
  dashboard: {
    autoRefresh: true,
    refreshInterval: 30,
    showWelcomeMessage: true,
    defaultView: 'overview',
    chartsAnimated: true,
    compactMode: false,
  },
  
  // Scanning
  scanning: {
    defaultTimeout: 300,
    maxConcurrentScans: 3,
    autoSaveReports: true,
    defaultReportFormat: 'html',
    includeScreenshots: false,
    detailedLogging: false,
  },
  
  // Security
  security: {
    sessionTimeout: 60,
    requirePasswordChange: false,
    passwordChangeInterval: 90,
    twoFactorEnabled: false,
    loginNotifications: true,
    ipWhitelist: [],
  },
  
  // Performance
  performance: {
    enableCaching: true,
    cacheTimeout: 15,
    lazyLoading: true,
    compressionEnabled: true,
    maxMemoryUsage: 512,
    backgroundSync: true,
  },
  
  // State management
  isLoading: false,
  error: null,
  hasUnsavedChanges: false,
};

// Settings Reducer
function settingsReducer(state: SettingsState, action: SettingsAction): SettingsState {
  switch (action.type) {
    case 'SETTINGS_LOAD_START':
      return {
        ...state,
        isLoading: true,
        error: null,
      };
      
    case 'SETTINGS_LOAD_SUCCESS':
      return {
        ...state,
        ...action.payload,
        isLoading: false,
        error: null,
        hasUnsavedChanges: false,
      };
      
    case 'SETTINGS_LOAD_FAILURE':
      return {
        ...state,
        isLoading: false,
        error: action.payload,
      };
      
    case 'SETTINGS_UPDATE':
      return {
        ...state,
        ...action.payload,
        hasUnsavedChanges: true,
      };
      
    case 'SETTINGS_SAVE_START':
      return {
        ...state,
        isLoading: true,
        error: null,
      };
      
    case 'SETTINGS_SAVE_SUCCESS':
      return {
        ...state,
        isLoading: false,
        error: null,
        hasUnsavedChanges: false,
      };
      
    case 'SETTINGS_SAVE_FAILURE':
      return {
        ...state,
        isLoading: false,
        error: action.payload,
      };
      
    case 'SETTINGS_RESET_TO_DEFAULT':
      return {
        ...defaultSettings,
        hasUnsavedChanges: true,
      };
      
    case 'SETTINGS_CLEAR_ERROR':
      return {
        ...state,
        error: null,
      };
      
    case 'SETTINGS_SET_UNSAVED':
      return {
        ...state,
        hasUnsavedChanges: action.payload,
      };
      
    default:
      return state;
  }
}

// Create Context
const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

// Settings Provider Props
interface SettingsProviderProps {
  children: ReactNode;
}

// Settings Provider Component
export const SettingsProvider: React.FC<SettingsProviderProps> = ({ children }) => {
  const [settings, dispatch] = useReducer(settingsReducer, defaultSettings);

  // Load Settings Function
  const loadSettings = useCallback(async (): Promise<void> => {
    try {
      dispatch({ type: 'SETTINGS_LOAD_START' });
      
      // Try to load from localStorage first
      const localSettings = localStorage.getItem('nexus_settings');
      if (localSettings) {
        const parsedSettings = JSON.parse(localSettings);
        dispatch({ type: 'SETTINGS_LOAD_SUCCESS', payload: parsedSettings });
      }
      
      // Then try to load from server
      const serverSettings = await settingsService.getSettings();
      dispatch({ type: 'SETTINGS_LOAD_SUCCESS', payload: serverSettings });
      
      // Update localStorage with server settings
      localStorage.setItem('nexus_settings', JSON.stringify(serverSettings));
      
      console.log('✅ Ayarlar yüklendi');
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Ayarlar yüklenirken hata oluştu';
      
      dispatch({ type: 'SETTINGS_LOAD_FAILURE', payload: errorMessage });
      
      console.error('❌ Ayar yükleme hatası:', errorMessage);
    }
  }, []);

  // Save Settings Function
  const saveSettings = useCallback(async (): Promise<void> => {
    try {
      dispatch({ type: 'SETTINGS_SAVE_START' });
      
      // Save to server
      await settingsService.updateSettings(settings);
      
      // Save to localStorage
      localStorage.setItem('nexus_settings', JSON.stringify(settings));
      
      dispatch({ type: 'SETTINGS_SAVE_SUCCESS' });
      
      console.log('✅ Ayarlar kaydedildi');
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Ayarlar kaydedilirken hata oluştu';
      
      dispatch({ type: 'SETTINGS_SAVE_FAILURE', payload: errorMessage });
      
      console.error('❌ Ayar kaydetme hatası:', errorMessage);
      throw error;
    }
  }, [settings]);

  // Update Settings Function
  const updateSettings = (updates: Partial<SettingsState>): void => {
    dispatch({ type: 'SETTINGS_UPDATE', payload: updates });
    
    // Auto-save to localStorage for immediate effect
    const updatedSettings = { ...settings, ...updates };
    localStorage.setItem('nexus_settings', JSON.stringify(updatedSettings));
  };

  // Reset to Defaults Function
  const resetToDefaults = (): void => {
    dispatch({ type: 'SETTINGS_RESET_TO_DEFAULT' });
    localStorage.setItem('nexus_settings', JSON.stringify(defaultSettings));
    console.log('✅ Ayarlar varsayılana sıfırlandı');
  };

  // Clear Error Function
  const clearError = (): void => {
    dispatch({ type: 'SETTINGS_CLEAR_ERROR' });
  };

  // Convenience Methods
  const toggleTheme = (): void => {
    const newTheme: ThemeMode = settings.theme === 'light' ? 'dark' : 
                               settings.theme === 'dark' ? 'system' : 'light';
    updateSettings({ theme: newTheme });
  };

  const setLanguage = (language: Language): void => {
    updateSettings({ language });
  };

  const toggleSidebar = (): void => {
    updateSettings({ sidebarCollapsed: !settings.sidebarCollapsed });
  };

  const updateNotificationSetting = (key: keyof NotificationSettings, value: boolean): void => {
    updateSettings({
      notifications: {
        ...settings.notifications,
        [key]: value,
      },
    });
  };

  const updateDashboardSetting = (key: keyof DashboardSettings, value: any): void => {
    updateSettings({
      dashboard: {
        ...settings.dashboard,
        [key]: value,
      },
    });
  };

  const updateScanSetting = (key: keyof ScanSettings, value: any): void => {
    updateSettings({
      scanning: {
        ...settings.scanning,
        [key]: value,
      },
    });
  };

  const updateSecuritySetting = (key: keyof SecuritySettings, value: any): void => {
    updateSettings({
      security: {
        ...settings.security,
        [key]: value,
      },
    });
  };

  const updatePerformanceSetting = (key: keyof PerformanceSettings, value: any): void => {
    updateSettings({
      performance: {
        ...settings.performance,
        [key]: value,
      },
    });
  };

  // Auto-save settings periodically
  useEffect(() => {
    let saveInterval: NodeJS.Timeout;
    
    if (settings.hasUnsavedChanges) {
      // Auto-save after 5 seconds of inactivity
      saveInterval = setTimeout(() => {
        saveSettings().catch((error) => {
          console.error('❌ Otomatik kaydetme hatası:', error);
        });
      }, 5000);
    }
    
    return () => {
      if (saveInterval) {
        clearTimeout(saveInterval);
      }
    };
  }, [settings.hasUnsavedChanges, saveSettings]);

  // Load settings on mount
  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  // Apply theme changes to document
  useEffect(() => {
    const applyTheme = () => {
      const root = document.documentElement;
      
      if (settings.theme === 'system') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
      } else {
        root.setAttribute('data-theme', settings.theme);
      }
      
      // Apply font size
      root.style.setProperty('--base-font-size', `${settings.fontSize}px`);
    };
    
    applyTheme();
    
    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleThemeChange = () => {
      if (settings.theme === 'system') {
        applyTheme();
      }
    };
    
    mediaQuery.addEventListener('change', handleThemeChange);
    
    return () => {
      mediaQuery.removeEventListener('change', handleThemeChange);
    };
  }, [settings.theme, settings.fontSize]);

  // Warn about unsaved changes before page unload
  useEffect(() => {
    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      if (settings.hasUnsavedChanges) {
        event.preventDefault();
        event.returnValue = 'Kaydedilmemiş değişiklikleriniz var. Sayfayı kapatmak istediğinizden emin misiniz?';
      }
    };
    
    window.addEventListener('beforeunload', handleBeforeUnload);
    
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [settings.hasUnsavedChanges]);

  // Context value
  const contextValue: SettingsContextType = {
    // State
    settings,
    isLoading: settings.isLoading,
    error: settings.error,
    hasUnsavedChanges: settings.hasUnsavedChanges,
    
    // Actions
    updateSettings,
    saveSettings,
    loadSettings,
    resetToDefaults,
    clearError,
    
    // Convenience methods
    toggleTheme,
    setLanguage,
    toggleSidebar,
    updateNotificationSetting,
    updateDashboardSetting,
    updateScanSetting,
    updateSecuritySetting,
    updatePerformanceSetting,
  };

  return (
    <SettingsContext.Provider value={contextValue}>
      {children}
    </SettingsContext.Provider>
  );
};

// Custom hook to use settings context
export const useSettings = (): SettingsContextType => {
  const context = useContext(SettingsContext);
  
  if (context === undefined) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  
  return context;
};

// Export context for testing
export { SettingsContext };

// Export types
export type {
  SettingsState,
  SettingsAction,
  SettingsContextType,
  NotificationSettings,
  DashboardSettings,
  ScanSettings,
  SecuritySettings,
  PerformanceSettings,
};