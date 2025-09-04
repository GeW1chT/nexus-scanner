// API Configuration
export const API_CONFIG = {
  BASE_URL: process.env['REACT_APP_API_URL'] || 'http://localhost:8000/api',
  TIMEOUT: 30000,
  RETRY_ATTEMPTS: 3,
  RETRY_DELAY: 1000,
} as const;

// WebSocket Configuration
export const WEBSOCKET_CONFIG = {
  URL: process.env['REACT_APP_WS_URL'] || 'ws://localhost:8000/ws',
  RECONNECT_INTERVAL: 5000,
  MAX_RECONNECT_ATTEMPTS: 10,
  HEARTBEAT_INTERVAL: 30000,
  CONNECTION_TIMEOUT: 10000,
} as const;

// Application Routes
export const ROUTES = {
  HOME: '/',
  LOGIN: '/login',
  REGISTER: '/register',
  FORGOT_PASSWORD: '/forgot-password',
  RESET_PASSWORD: '/reset-password',
  VERIFY_EMAIL: '/verify-email',
  DASHBOARD: '/dashboard',
  TARGETS: '/targets',
  TARGET_DETAIL: '/targets/:id',
  SCANS: '/scans',
  SCAN_DETAIL: '/scans/:id',
  VULNERABILITIES: '/vulnerabilities',
  VULNERABILITY_DETAIL: '/vulnerabilities/:id',
  REPORTS: '/reports',
  REPORT_DETAIL: '/reports/:id',
  NOTIFICATIONS: '/notifications',
  SETTINGS: '/settings',
  PROFILE: '/profile',
  HELP: '/help',
  ABOUT: '/about',
} as const;

// Local Storage Keys
export const STORAGE_KEYS = {
  AUTH_TOKEN: 'nexus_auth_token',
  REFRESH_TOKEN: 'nexus_refresh_token',
  USER_DATA: 'nexus_user_data',
  SETTINGS: 'nexus_settings',
  THEME: 'nexus_theme',
  LANGUAGE: 'nexus_language',
  SIDEBAR_COLLAPSED: 'nexus_sidebar_collapsed',
  RECENT_SEARCHES: 'nexus_recent_searches',
  DASHBOARD_LAYOUT: 'nexus_dashboard_layout',
  TABLE_PREFERENCES: 'nexus_table_preferences',
} as const;

// Query Keys for React Query
export const QUERY_KEYS = {
  // Auth
  USER: ['user'],
  USER_PROFILE: ['user', 'profile'],
  USER_PERMISSIONS: ['user', 'permissions'],
  
  // Targets
  TARGETS: ['targets'],
  TARGET: (id: string) => ['targets', id],
  TARGET_SCANS: (id: string) => ['targets', id, 'scans'],
  TARGET_VULNERABILITIES: (id: string) => ['targets', id, 'vulnerabilities'],
  
  // Scans
  SCANS: ['scans'],
  SCAN: (id: string) => ['scans', id],
  SCAN_RESULTS: (id: string) => ['scans', id, 'results'],
  SCAN_LOGS: (id: string) => ['scans', id, 'logs'],
  ACTIVE_SCANS: ['scans', 'active'],
  
  // Vulnerabilities
  VULNERABILITIES: ['vulnerabilities'],
  VULNERABILITY: (id: string) => ['vulnerabilities', id],
  VULNERABILITY_STATS: ['vulnerabilities', 'stats'],
  
  // Reports
  REPORTS: ['reports'],
  REPORT: (id: string) => ['reports', id],
  REPORT_TEMPLATES: ['reports', 'templates'],
  
  // Dashboard
  DASHBOARD_STATS: ['dashboard', 'stats'],
  DASHBOARD_ACTIVITY: ['dashboard', 'activity'],
  DASHBOARD_CHARTS: ['dashboard', 'charts'],
  
  // Notifications
  NOTIFICATIONS: ['notifications'],
  NOTIFICATION_COUNT: ['notifications', 'count'],
  
  // Settings
  SETTINGS: ['settings'],
  SYSTEM_INFO: ['system', 'info'],
  SYSTEM_HEALTH: ['system', 'health'],
  
  // Search
  SEARCH: (query: string) => ['search', query],
  SEARCH_SUGGESTIONS: ['search', 'suggestions'],
} as const;

// Scan Types
export const SCAN_TYPES = {
  QUICK: 'quick',
  FULL: 'full',
  CUSTOM: 'custom',
  SCHEDULED: 'scheduled',
} as const;

// Scan Status
export const SCAN_STATUS = {
  PENDING: 'pending',
  RUNNING: 'running',
  PAUSED: 'paused',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
} as const;

// Vulnerability Severity
export const VULNERABILITY_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
} as const;

// Vulnerability Status
export const VULNERABILITY_STATUS = {
  OPEN: 'open',
  CONFIRMED: 'confirmed',
  FALSE_POSITIVE: 'false_positive',
  FIXED: 'fixed',
  ACCEPTED_RISK: 'accepted_risk',
} as const;

// Target Types
export const TARGET_TYPES = {
  WEBSITE: 'website',
  API: 'api',
  NETWORK: 'network',
  MOBILE_APP: 'mobile_app',
} as const;

// Report Formats
export const REPORT_FORMATS = {
  PDF: 'pdf',
  HTML: 'html',
  JSON: 'json',
  CSV: 'csv',
  XML: 'xml',
} as const;

// Notification Types
export const NOTIFICATION_TYPES = {
  SCAN_COMPLETED: 'scan_completed',
  SCAN_FAILED: 'scan_failed',
  VULNERABILITY_FOUND: 'vulnerability_found',
  REPORT_GENERATED: 'report_generated',
  SYSTEM_ALERT: 'system_alert',
  SECURITY_ALERT: 'security_alert',
} as const;

// Theme Options
export const THEMES = {
  LIGHT: 'light',
  DARK: 'dark',
  SYSTEM: 'system',
} as const;

// Language Options
export const LANGUAGES = {
  TR: 'tr',
  EN: 'en',
} as const;

// Date Formats
export const DATE_FORMATS = {
  SHORT: 'DD/MM/YYYY',
  LONG: 'DD MMMM YYYY',
  WITH_TIME: 'DD/MM/YYYY HH:mm',
  TIME_ONLY: 'HH:mm:ss',
  ISO: 'YYYY-MM-DDTHH:mm:ss.SSSZ',
} as const;

// Pagination
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 20,
  PAGE_SIZE_OPTIONS: [10, 20, 50, 100],
  MAX_PAGE_SIZE: 1000,
} as const;

// File Upload
export const FILE_UPLOAD = {
  MAX_SIZE: 10 * 1024 * 1024, // 10MB
  ALLOWED_TYPES: {
    IMAGES: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    DOCUMENTS: ['application/pdf', 'text/plain', 'application/json'],
    ARCHIVES: ['application/zip', 'application/x-tar', 'application/gzip'],
  },
  CHUNK_SIZE: 1024 * 1024, // 1MB chunks
} as const;

// Validation Rules
export const VALIDATION = {
  PASSWORD: {
    MIN_LENGTH: 8,
    MAX_LENGTH: 128,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true,
  },
  USERNAME: {
    MIN_LENGTH: 3,
    MAX_LENGTH: 50,
    PATTERN: /^[a-zA-Z0-9_-]+$/,
  },
  EMAIL: {
    PATTERN: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  },
  URL: {
    PATTERN: /^https?:\/\/.+/,
  },
  IP_ADDRESS: {
    IPV4_PATTERN: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    IPV6_PATTERN: /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
  },
} as const;

// Error Messages
export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Ağ bağlantısı hatası. Lütfen internet bağlantınızı kontrol edin.',
  SERVER_ERROR: 'Sunucu hatası. Lütfen daha sonra tekrar deneyin.',
  UNAUTHORIZED: 'Bu işlem için yetkiniz bulunmuyor.',
  FORBIDDEN: 'Bu kaynağa erişim izniniz yok.',
  NOT_FOUND: 'Aradığınız kaynak bulunamadı.',
  VALIDATION_ERROR: 'Girilen bilgiler geçersiz.',
  TIMEOUT_ERROR: 'İşlem zaman aşımına uğradı.',
  UNKNOWN_ERROR: 'Bilinmeyen bir hata oluştu.',
  
  // Auth specific
  INVALID_CREDENTIALS: 'Geçersiz kullanıcı adı veya şifre.',
  ACCOUNT_LOCKED: 'Hesabınız kilitlenmiştir.',
  EMAIL_NOT_VERIFIED: 'E-posta adresiniz doğrulanmamış.',
  PASSWORD_EXPIRED: 'Şifrenizin süresi dolmuş.',
  
  // Validation specific
  REQUIRED_FIELD: 'Bu alan zorunludur.',
  INVALID_EMAIL: 'Geçersiz e-posta adresi.',
  INVALID_URL: 'Geçersiz URL formatı.',
  INVALID_IP: 'Geçersiz IP adresi.',
  PASSWORD_TOO_WEAK: 'Şifre çok zayıf.',
  PASSWORDS_NOT_MATCH: 'Şifreler eşleşmiyor.',
  FILE_TOO_LARGE: 'Dosya boyutu çok büyük.',
  INVALID_FILE_TYPE: 'Geçersiz dosya türü.',
} as const;

// Success Messages
export const SUCCESS_MESSAGES = {
  SAVE_SUCCESS: 'Başarıyla kaydedildi.',
  UPDATE_SUCCESS: 'Başarıyla güncellendi.',
  DELETE_SUCCESS: 'Başarıyla silindi.',
  COPY_SUCCESS: 'Panoya kopyalandı.',
  UPLOAD_SUCCESS: 'Dosya başarıyla yüklendi.',
  DOWNLOAD_SUCCESS: 'Dosya başarıyla indirildi.',
  EMAIL_SENT: 'E-posta başarıyla gönderildi.',
  PASSWORD_CHANGED: 'Şifre başarıyla değiştirildi.',
  PROFILE_UPDATED: 'Profil başarıyla güncellendi.',
  SETTINGS_SAVED: 'Ayarlar başarıyla kaydedildi.',
  SCAN_STARTED: 'Tarama başlatıldı.',
  SCAN_STOPPED: 'Tarama durduruldu.',
  REPORT_GENERATED: 'Rapor oluşturuldu.',
} as const;

// Loading Messages
export const LOADING_MESSAGES = {
  LOADING: 'Yükleniyor...',
  SAVING: 'Kaydediliyor...',
  UPDATING: 'Güncelleniyor...',
  DELETING: 'Siliniyor...',
  UPLOADING: 'Yükleniyor...',
  DOWNLOADING: 'İndiriliyor...',
  PROCESSING: 'İşleniyor...',
  CONNECTING: 'Bağlanıyor...',
  SCANNING: 'Taranıyor...',
  GENERATING: 'Oluşturuluyor...',
} as const;

// Colors
export const COLORS = {
  PRIMARY: '#1976d2',
  SECONDARY: '#dc004e',
  SUCCESS: '#2e7d32',
  WARNING: '#ed6c02',
  ERROR: '#d32f2f',
  INFO: '#0288d1',
  
  // Severity colors
  SEVERITY: {
    CRITICAL: '#d32f2f',
    HIGH: '#f57c00',
    MEDIUM: '#fbc02d',
    LOW: '#388e3c',
    INFO: '#1976d2',
  },
  
  // Status colors
  STATUS: {
    RUNNING: '#1976d2',
    COMPLETED: '#2e7d32',
    FAILED: '#d32f2f',
    PAUSED: '#ed6c02',
    PENDING: '#757575',
    CANCELLED: '#424242',
  },
  
  // Chart colors
  CHART: [
    '#1976d2',
    '#dc004e',
    '#2e7d32',
    '#ed6c02',
    '#9c27b0',
    '#00acc1',
    '#f57c00',
    '#5e35b1',
    '#43a047',
    '#fb8c00',
  ],
} as const;

// Chart Configuration
export const CHART_CONFIG = {
  ANIMATION_DURATION: 300,
  TOOLTIP_DELAY: 100,
  LEGEND_POSITION: 'bottom',
  GRID_COLOR: '#e0e0e0',
  TEXT_COLOR: '#424242',
  FONT_FAMILY: 'Roboto, Arial, sans-serif',
} as const;

// Table Configuration
export const TABLE_CONFIG = {
  DEFAULT_PAGE_SIZE: 20,
  ROW_HEIGHT: 52,
  HEADER_HEIGHT: 56,
  CHECKBOX_COLUMN_WIDTH: 58,
  ACTIONS_COLUMN_WIDTH: 120,
  MIN_COLUMN_WIDTH: 100,
  MAX_COLUMN_WIDTH: 400,
} as const;

// Animation Durations
export const ANIMATION = {
  FAST: 150,
  NORMAL: 300,
  SLOW: 500,
  EXTRA_SLOW: 1000,
} as const;

// Breakpoints
export const BREAKPOINTS = {
  XS: 0,
  SM: 600,
  MD: 900,
  LG: 1200,
  XL: 1536,
} as const;

// Z-Index Layers
export const Z_INDEX = {
  DROPDOWN: 1000,
  STICKY: 1020,
  FIXED: 1030,
  MODAL_BACKDROP: 1040,
  MODAL: 1050,
  POPOVER: 1060,
  TOOLTIP: 1070,
  TOAST: 1080,
} as const;

// Keyboard Shortcuts
export const KEYBOARD_SHORTCUTS = {
  SEARCH: 'ctrl+k',
  NEW_SCAN: 'ctrl+n',
  REFRESH: 'f5',
  SAVE: 'ctrl+s',
  COPY: 'ctrl+c',
  PASTE: 'ctrl+v',
  UNDO: 'ctrl+z',
  REDO: 'ctrl+y',
  SELECT_ALL: 'ctrl+a',
  CLOSE_MODAL: 'escape',
  NEXT_TAB: 'ctrl+tab',
  PREV_TAB: 'ctrl+shift+tab',
} as const;

// Feature Flags
export const FEATURES = {
  DARK_MODE: true,
  NOTIFICATIONS: true,
  WEBSOCKETS: true,
  FILE_UPLOAD: true,
  EXPORT: true,
  ADVANCED_SEARCH: true,
  BULK_OPERATIONS: true,
  KEYBOARD_SHORTCUTS: true,
  ANALYTICS: false,
  BETA_FEATURES: false,
} as const;

// Environment
export const ENV = {
  DEVELOPMENT: process.env['NODE_ENV'] === 'development',
  PRODUCTION: process.env['NODE_ENV'] === 'production',
  TEST: process.env['NODE_ENV'] === 'test',
} as const;

// Application Metadata
export const APP_INFO = {
  NAME: 'Nexus Scanner',
  VERSION: process.env['REACT_APP_VERSION'] || '1.0.0',
  DESCRIPTION: 'Kapsamlı güvenlik açığı tarama ve analiz platformu',
  AUTHOR: 'Nexus Security Team',
  HOMEPAGE: 'https://nexus-scanner.com',
  SUPPORT_EMAIL: 'support@nexus-scanner.com',
  DOCUMENTATION_URL: 'https://docs.nexus-scanner.com',
  GITHUB_URL: 'https://github.com/nexus-scanner/nexus-scanner',
} as const;

// Export all constants as default object
const constants = {
  API_CONFIG,
  WEBSOCKET_CONFIG,
  ROUTES,
  STORAGE_KEYS,
  QUERY_KEYS,
  SCAN_TYPES,
  SCAN_STATUS,
  VULNERABILITY_SEVERITY,
  VULNERABILITY_STATUS,
  TARGET_TYPES,
  REPORT_FORMATS,
  NOTIFICATION_TYPES,
  THEMES,
  LANGUAGES,
  DATE_FORMATS,
  PAGINATION,
  FILE_UPLOAD,
  VALIDATION,
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
  LOADING_MESSAGES,
  COLORS,
  CHART_CONFIG,
  TABLE_CONFIG,
  ANIMATION,
  BREAKPOINTS,
  Z_INDEX,
  KEYBOARD_SHORTCUTS,
  FEATURES,
  ENV,
  APP_INFO,
};

export default constants;