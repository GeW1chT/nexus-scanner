// User Interface
export interface User {
  id: number;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  isActive: boolean;
  isVerified: boolean;
  lastLogin: string | null;
  createdAt: string;
  updatedAt: string;
  avatar?: string;
  preferences?: UserPreferences;
  permissions?: Permission[];
}

// User Role Enum
export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  VIEWER = 'viewer',
  ANALYST = 'analyst',
}

// User Preferences Interface
export interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  language: 'tr' | 'en';
  timezone: string;
  notifications: {
    email: boolean;
    push: boolean;
    scanComplete: boolean;
    vulnerabilityFound: boolean;
  };
  dashboard: {
    defaultView: string;
    autoRefresh: boolean;
    refreshInterval: number;
  };
}

// Permission Interface
export interface Permission {
  id: number;
  name: string;
  description: string;
  resource: string;
  action: string;
}

// Login Credentials Interface
export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
  twoFactorCode?: string;
}

// Register Data Interface
export interface RegisterData {
  email: string;
  username: string;
  full_name: string;
  password: string;
  role: string;
}

// Auth Response Interface
export interface AuthResponse {
  user: User;
  token: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

// Token Payload Interface
export interface TokenPayload {
  sub: number; // user id
  email: string;
  role: UserRole;
  iat: number; // issued at
  exp: number; // expires at
  jti: string; // JWT ID
}

// Password Reset Request Interface
export interface PasswordResetRequest {
  email: string;
}

// Password Reset Confirm Interface
export interface PasswordResetConfirm {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

// Change Password Interface
export interface ChangePasswordData {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

// Update Profile Interface
export interface UpdateProfileData {
  firstName?: string;
  lastName?: string;
  username?: string;
  avatar?: string;
  preferences?: Partial<UserPreferences>;
}

// Email Verification Interface
export interface EmailVerificationData {
  token: string;
}

// Two Factor Auth Setup Interface
export interface TwoFactorSetupData {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

// Two Factor Auth Verify Interface
export interface TwoFactorVerifyData {
  code: string;
}

// Session Info Interface
export interface SessionInfo {
  id: string;
  userId: number;
  ipAddress: string;
  userAgent: string;
  location?: string;
  isActive: boolean;
  lastActivity: string;
  createdAt: string;
}

// Login History Interface
export interface LoginHistory {
  id: number;
  userId: number;
  ipAddress: string;
  userAgent: string;
  location?: string;
  success: boolean;
  failureReason?: string;
  timestamp: string;
}

// Account Security Interface
export interface AccountSecurity {
  twoFactorEnabled: boolean;
  lastPasswordChange: string;
  activeSessions: SessionInfo[];
  recentLogins: LoginHistory[];
  securityEvents: SecurityEvent[];
}

// Security Event Interface
export interface SecurityEvent {
  id: number;
  userId: number;
  type: SecurityEventType;
  description: string;
  ipAddress: string;
  userAgent: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  resolved: boolean;
}

// Security Event Type Enum
export enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  PASSWORD_CHANGE = 'password_change',
  EMAIL_CHANGE = 'email_change',
  TWO_FACTOR_ENABLED = 'two_factor_enabled',
  TWO_FACTOR_DISABLED = 'two_factor_disabled',
  SUSPICIOUS_LOGIN = 'suspicious_login',
  ACCOUNT_LOCKED = 'account_locked',
  ACCOUNT_UNLOCKED = 'account_unlocked',
  PERMISSION_CHANGE = 'permission_change',
}

// Auth Error Interface
export interface AuthError {
  code: string;
  message: string;
  field?: string;
  details?: Record<string, any>;
}

// Auth State Interface
export interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: AuthError | null;
  lastActivity: string | null;
}

// Login Form Validation Schema
export interface LoginFormData {
  email: string;
  password: string;
  rememberMe: boolean;
}

// Register Form Validation Schema
export interface RegisterFormData {
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  password: string;
  confirmPassword: string;
  acceptTerms: boolean;
  newsletter: boolean;
}

// Profile Form Validation Schema
export interface ProfileFormData {
  firstName: string;
  lastName: string;
  username: string;
  email: string;
  avatar?: File | string;
}

// Password Form Validation Schema
export interface PasswordFormData {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

// Preferences Form Validation Schema
export interface PreferencesFormData {
  theme: 'light' | 'dark' | 'system';
  language: 'tr' | 'en';
  timezone: string;
  emailNotifications: boolean;
  pushNotifications: boolean;
  scanCompleteNotifications: boolean;
  vulnerabilityNotifications: boolean;
  defaultDashboardView: string;
  autoRefreshDashboard: boolean;
  dashboardRefreshInterval: number;
}

// API Response Types
export interface LoginResponse extends AuthResponse {}
export interface RegisterResponse extends AuthResponse {}
export interface RefreshTokenResponse {
  token: string;
  refreshToken: string;
  expiresIn: number;
}

export interface UserProfileResponse {
  user: User;
}

export interface SecuritySettingsResponse {
  security: AccountSecurity;
}

// Utility Types
export type AuthAction = 
  | 'login'
  | 'register'
  | 'logout'
  | 'refresh'
  | 'update_profile'
  | 'change_password'
  | 'verify_email'
  | 'reset_password'
  | 'setup_2fa'
  | 'disable_2fa';

export type AuthStatus = 
  | 'idle'
  | 'loading'
  | 'authenticated'
  | 'unauthenticated'
  | 'error';

// Constants
export const USER_ROLES = {
  ADMIN: 'admin' as const,
  USER: 'user' as const,
  VIEWER: 'viewer' as const,
  ANALYST: 'analyst' as const,
};

export const PERMISSIONS = {
  // User Management
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',
  
  // Target Management
  TARGET_CREATE: 'target:create',
  TARGET_READ: 'target:read',
  TARGET_UPDATE: 'target:update',
  TARGET_DELETE: 'target:delete',
  
  // Scan Management
  SCAN_CREATE: 'scan:create',
  SCAN_READ: 'scan:read',
  SCAN_UPDATE: 'scan:update',
  SCAN_DELETE: 'scan:delete',
  SCAN_EXECUTE: 'scan:execute',
  
  // Report Management
  REPORT_CREATE: 'report:create',
  REPORT_READ: 'report:read',
  REPORT_UPDATE: 'report:update',
  REPORT_DELETE: 'report:delete',
  REPORT_EXPORT: 'report:export',
  
  // System Administration
  SYSTEM_CONFIG: 'system:config',
  SYSTEM_LOGS: 'system:logs',
  SYSTEM_BACKUP: 'system:backup',
  SYSTEM_RESTORE: 'system:restore',
} as const;

export const TOKEN_STORAGE_KEY = 'nexus_token';
export const REFRESH_TOKEN_STORAGE_KEY = 'nexus_refresh_token';
export const USER_STORAGE_KEY = 'nexus_user';

// Type Guards
export const isUser = (obj: any): obj is User => {
  return obj && 
    typeof obj.id === 'number' &&
    typeof obj.email === 'string' &&
    typeof obj.username === 'string' &&
    Object.values(UserRole).includes(obj.role);
};

export const isAuthResponse = (obj: any): obj is AuthResponse => {
  return obj &&
    isUser(obj.user) &&
    typeof obj.token === 'string' &&
    typeof obj.refreshToken === 'string';
};

export const isTokenPayload = (obj: any): obj is TokenPayload => {
  return obj &&
    typeof obj.sub === 'number' &&
    typeof obj.email === 'string' &&
    Object.values(UserRole).includes(obj.role) &&
    typeof obj.iat === 'number' &&
    typeof obj.exp === 'number';
};

// Helper Functions
export const hasPermission = (user: User, permission: string): boolean => {
  if (!user.permissions) return false;
  return user.permissions.some(p => `${p.resource}:${p.action}` === permission);
};

export const hasRole = (user: User, role: UserRole): boolean => {
  return user.role === role;
};

export const isAdmin = (user: User): boolean => {
  return hasRole(user, UserRole.ADMIN);
};

export const canManageUsers = (user: User): boolean => {
  return isAdmin(user) || hasPermission(user, PERMISSIONS.USER_CREATE);
};

export const canExecuteScans = (user: User): boolean => {
  return hasPermission(user, PERMISSIONS.SCAN_EXECUTE) || 
         hasRole(user, UserRole.ADMIN) || 
         hasRole(user, UserRole.ANALYST);
};

export const canViewReports = (user: User): boolean => {
  return hasPermission(user, PERMISSIONS.REPORT_READ) ||
         hasRole(user, UserRole.ADMIN) ||
         hasRole(user, UserRole.ANALYST) ||
         hasRole(user, UserRole.VIEWER);
};

export const getDisplayName = (user: User): string => {
  return `${user.firstName} ${user.lastName}`.trim() || user.username || user.email;
};

export const getInitials = (user: User): string => {
  const firstName = user.firstName?.charAt(0)?.toUpperCase() || '';
  const lastName = user.lastName?.charAt(0)?.toUpperCase() || '';
  return firstName + lastName || user.username?.charAt(0)?.toUpperCase() || user.email?.charAt(0)?.toUpperCase() || '?';
};

export const isTokenExpired = (token: string): boolean => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return true;
    const payload = JSON.parse(atob(parts[1]!)) as TokenPayload;
    return Date.now() >= payload.exp * 1000;
  } catch {
    return true;
  }
};

export const getTokenExpirationTime = (token: string): Date | null => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]!)) as TokenPayload;
    return new Date(payload.exp * 1000);
  } catch {
    return null;
  }
};