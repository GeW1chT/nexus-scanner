import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { ApiResponse } from '../types/api';
import {
  SettingsState,
  NotificationSettings,
  DashboardSettings,
  ScanSettings,
  SecuritySettings,
  PerformanceSettings,
} from '../contexts/SettingsContext';

// API Base URL
const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:8000/api';

// Settings API Response Interfaces
interface SettingsResponse {
  settings: SettingsState;
}

interface NotificationSettingsResponse {
  notifications: NotificationSettings;
}

interface DashboardSettingsResponse {
  dashboard: DashboardSettings;
}

interface ScanSettingsResponse {
  scanning: ScanSettings;
}

interface SecuritySettingsResponse {
  security: SecuritySettings;
}

interface PerformanceSettingsResponse {
  performance: PerformanceSettings;
}

// Settings Service Class
export class SettingsService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  // Setup Axios Interceptors
  private setupInterceptors(): void {
    // Request Interceptor - Add auth token
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('nexus_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response Interceptor - Handle errors
    this.api.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          // Token expired, dispatch event
          window.dispatchEvent(new CustomEvent('token-expired'));
        }
        return Promise.reject(error);
      }
    );
  }

  // Get All Settings
  public async getSettings(): Promise<SettingsState> {
    try {
      const response: AxiosResponse<ApiResponse<SettingsResponse>> = await this.api.get(
        '/settings'
      );

      return response.data.data.settings;
    } catch (error: any) {
      console.error('❌ Get settings error:', error.response?.data || error.message);
      
      // Return default settings if API fails
      return this.getDefaultSettings();
    }
  }

  // Update All Settings
  public async updateSettings(settings: Partial<SettingsState>): Promise<SettingsState> {
    try {
      const response: AxiosResponse<ApiResponse<SettingsResponse>> = await this.api.put(
        '/settings',
        { settings }
      );

      return response.data.data.settings;
    } catch (error: any) {
      console.error('❌ Update settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Notification Settings
  public async getNotificationSettings(): Promise<NotificationSettings> {
    try {
      const response: AxiosResponse<ApiResponse<NotificationSettingsResponse>> = await this.api.get(
        '/settings/notifications'
      );

      return response.data.data.notifications;
    } catch (error: any) {
      console.error('❌ Get notification settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Update Notification Settings
  public async updateNotificationSettings(notifications: Partial<NotificationSettings>): Promise<NotificationSettings> {
    try {
      const response: AxiosResponse<ApiResponse<NotificationSettingsResponse>> = await this.api.put(
        '/settings/notifications',
        { notifications }
      );

      return response.data.data.notifications;
    } catch (error: any) {
      console.error('❌ Update notification settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Dashboard Settings
  public async getDashboardSettings(): Promise<DashboardSettings> {
    try {
      const response: AxiosResponse<ApiResponse<DashboardSettingsResponse>> = await this.api.get(
        '/settings/dashboard'
      );

      return response.data.data.dashboard;
    } catch (error: any) {
      console.error('❌ Get dashboard settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Update Dashboard Settings
  public async updateDashboardSettings(dashboard: Partial<DashboardSettings>): Promise<DashboardSettings> {
    try {
      const response: AxiosResponse<ApiResponse<DashboardSettingsResponse>> = await this.api.put(
        '/settings/dashboard',
        { dashboard }
      );

      return response.data.data.dashboard;
    } catch (error: any) {
      console.error('❌ Update dashboard settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Scan Settings
  public async getScanSettings(): Promise<ScanSettings> {
    try {
      const response: AxiosResponse<ApiResponse<ScanSettingsResponse>> = await this.api.get(
        '/settings/scanning'
      );

      return response.data.data.scanning;
    } catch (error: any) {
      console.error('❌ Get scan settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Update Scan Settings
  public async updateScanSettings(scanning: Partial<ScanSettings>): Promise<ScanSettings> {
    try {
      const response: AxiosResponse<ApiResponse<ScanSettingsResponse>> = await this.api.put(
        '/settings/scanning',
        { scanning }
      );

      return response.data.data.scanning;
    } catch (error: any) {
      console.error('❌ Update scan settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Security Settings
  public async getSecuritySettings(): Promise<SecuritySettings> {
    try {
      const response: AxiosResponse<ApiResponse<SecuritySettingsResponse>> = await this.api.get(
        '/settings/security'
      );

      return response.data.data.security;
    } catch (error: any) {
      console.error('❌ Get security settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Update Security Settings
  public async updateSecuritySettings(security: Partial<SecuritySettings>): Promise<SecuritySettings> {
    try {
      const response: AxiosResponse<ApiResponse<SecuritySettingsResponse>> = await this.api.put(
        '/settings/security',
        { security }
      );

      return response.data.data.security;
    } catch (error: any) {
      console.error('❌ Update security settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Performance Settings
  public async getPerformanceSettings(): Promise<PerformanceSettings> {
    try {
      const response: AxiosResponse<ApiResponse<PerformanceSettingsResponse>> = await this.api.get(
        '/settings/performance'
      );

      return response.data.data.performance;
    } catch (error: any) {
      console.error('❌ Get performance settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Update Performance Settings
  public async updatePerformanceSettings(performance: Partial<PerformanceSettings>): Promise<PerformanceSettings> {
    try {
      const response: AxiosResponse<ApiResponse<PerformanceSettingsResponse>> = await this.api.put(
        '/settings/performance',
        { performance }
      );

      return response.data.data.performance;
    } catch (error: any) {
      console.error('❌ Update performance settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Reset Settings to Default
  public async resetToDefaults(): Promise<SettingsState> {
    try {
      const response: AxiosResponse<ApiResponse<SettingsResponse>> = await this.api.post(
        '/settings/reset'
      );

      return response.data.data.settings;
    } catch (error: any) {
      console.error('❌ Reset settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Export Settings
  public async exportSettings(): Promise<Blob> {
    try {
      const response: AxiosResponse<Blob> = await this.api.get(
        '/settings/export',
        {
          responseType: 'blob',
        }
      );

      return response.data;
    } catch (error: any) {
      console.error('❌ Export settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Import Settings
  public async importSettings(file: File): Promise<SettingsState> {
    try {
      const formData = new FormData();
      formData.append('settings', file);

      const response: AxiosResponse<ApiResponse<SettingsResponse>> = await this.api.post(
        '/settings/import',
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      return response.data.data.settings;
    } catch (error: any) {
      console.error('❌ Import settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Validate Settings
  public async validateSettings(settings: Partial<SettingsState>): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const response: AxiosResponse<ApiResponse<{ valid: boolean; errors: string[] }>> = await this.api.post(
        '/settings/validate',
        { settings }
      );

      return response.data.data;
    } catch (error: any) {
      console.error('❌ Validate settings error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Settings Schema
  public async getSettingsSchema(): Promise<Record<string, any>> {
    try {
      const response: AxiosResponse<ApiResponse<Record<string, any>>> = await this.api.get(
        '/settings/schema'
      );

      return response.data.data;
    } catch (error: any) {
      console.error('❌ Get settings schema error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Default Settings
  private getDefaultSettings(): SettingsState {
    return {
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
  }

  // Local Storage Helpers
  public saveToLocalStorage(settings: SettingsState): void {
    try {
      localStorage.setItem('nexus_settings', JSON.stringify(settings));
    } catch (error) {
      console.error('❌ Save settings to localStorage error:', error);
    }
  }

  public loadFromLocalStorage(): SettingsState | null {
    try {
      const stored = localStorage.getItem('nexus_settings');
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.error('❌ Load settings from localStorage error:', error);
    }
    return null;
  }

  public clearLocalStorage(): void {
    try {
      localStorage.removeItem('nexus_settings');
    } catch (error) {
      console.error('❌ Clear settings from localStorage error:', error);
    }
  }

  // Theme Helpers
  public applyTheme(theme: 'light' | 'dark' | 'system'): void {
    const root = document.documentElement;
    
    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    } else {
      root.setAttribute('data-theme', theme);
    }
  }

  public getCurrentTheme(): 'light' | 'dark' {
    const root = document.documentElement;
    return root.getAttribute('data-theme') as 'light' | 'dark' || 'light';
  }

  // Language Helpers
  public applyLanguage(language: 'tr' | 'en'): void {
    document.documentElement.lang = language;
    
    // Update moment.js locale if available
    if (typeof window !== 'undefined' && (window as any).moment) {
      (window as any).moment.locale(language === 'tr' ? 'tr' : 'en');
    }
  }

  // Font Size Helpers
  public applyFontSize(fontSize: number): void {
    const root = document.documentElement;
    root.style.setProperty('--base-font-size', `${fontSize}px`);
  }

  // Validation Helpers
  public validateNotificationSettings(_settings: Partial<NotificationSettings>): string[] {
    const errors: string[] = [];
    
    // Add validation logic here if needed
    
    return errors;
  }

  public validateDashboardSettings(settings: Partial<DashboardSettings>): string[] {
    const errors: string[] = [];
    
    if (settings.refreshInterval && (settings.refreshInterval < 5 || settings.refreshInterval > 300)) {
      errors.push('Yenileme aralığı 5-300 saniye arasında olmalıdır');
    }
    
    return errors;
  }

  public validateScanSettings(settings: Partial<ScanSettings>): string[] {
    const errors: string[] = [];
    
    if (settings.defaultTimeout && (settings.defaultTimeout < 30 || settings.defaultTimeout > 3600)) {
      errors.push('Varsayılan zaman aşımı 30-3600 saniye arasında olmalıdır');
    }
    
    if (settings.maxConcurrentScans && (settings.maxConcurrentScans < 1 || settings.maxConcurrentScans > 10)) {
      errors.push('Maksimum eşzamanlı tarama sayısı 1-10 arasında olmalıdır');
    }
    
    return errors;
  }

  public validateSecuritySettings(settings: Partial<SecuritySettings>): string[] {
    const errors: string[] = [];
    
    if (settings.sessionTimeout && (settings.sessionTimeout < 5 || settings.sessionTimeout > 1440)) {
      errors.push('Oturum zaman aşımı 5-1440 dakika arasında olmalıdır');
    }
    
    if (settings.passwordChangeInterval && (settings.passwordChangeInterval < 1 || settings.passwordChangeInterval > 365)) {
      errors.push('Şifre değiştirme aralığı 1-365 gün arasında olmalıdır');
    }
    
    return errors;
  }

  public validatePerformanceSettings(settings: Partial<PerformanceSettings>): string[] {
    const errors: string[] = [];
    
    if (settings.cacheTimeout && (settings.cacheTimeout < 1 || settings.cacheTimeout > 60)) {
      errors.push('Önbellek zaman aşımı 1-60 dakika arasında olmalıdır');
    }
    
    if (settings.maxMemoryUsage && (settings.maxMemoryUsage < 128 || settings.maxMemoryUsage > 2048)) {
      errors.push('Maksimum bellek kullanımı 128-2048 MB arasında olmalıdır');
    }
    
    return errors;
  }
}

// Create and export singleton instance
export const settingsService = new SettingsService();

// Export default
export default settingsService;