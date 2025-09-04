import axios, { AxiosInstance, AxiosResponse } from 'axios';
import {
  User,
  LoginCredentials,
  RegisterData,
  AuthResponse,
  PasswordResetRequest,
  PasswordResetConfirm,
  ChangePasswordData,
  UpdateProfileData,
  EmailVerificationData,
  TwoFactorSetupData,
  TwoFactorVerifyData,
  AccountSecurity,
  SessionInfo,
  RefreshTokenResponse,
  UserProfileResponse,
  SecuritySettingsResponse,
  TOKEN_STORAGE_KEY,
  REFRESH_TOKEN_STORAGE_KEY,
  isTokenExpired,
} from '../types/auth';
import { ApiResponse } from '../types/api';

// API Base URL
const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:8000/api';

// Auth Service Class
export class AuthService {
  private api: AxiosInstance;
  private refreshPromise: Promise<string> | null = null;

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
        const token = localStorage.getItem(TOKEN_STORAGE_KEY);
        if (token && !isTokenExpired(token)) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response Interceptor - Handle token refresh
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const newToken = await this.handleTokenRefresh();
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return this.api(originalRequest);
          } catch (refreshError) {
            // Refresh failed, redirect to login
            this.handleAuthFailure();
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  // Handle Token Refresh
  private async handleTokenRefresh(): Promise<string> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.performTokenRefresh();
    
    try {
      const token = await this.refreshPromise;
      return token;
    } finally {
      this.refreshPromise = null;
    }
  }

  // Perform Token Refresh
  private async performTokenRefresh(): Promise<string> {
    const refreshToken = localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await axios.post<ApiResponse<RefreshTokenResponse>>(
        `${API_BASE_URL}/auth/refresh`,
        { refreshToken },
        { timeout: 10000 }
      );

      const { token, refreshToken: newRefreshToken } = response.data.data;
      
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
      localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, newRefreshToken);
      
      console.log('✅ Token başarıyla yenilendi');
      return token;
    } catch (error) {
      console.error('❌ Token yenileme hatası:', error);
      throw error;
    }
  }

  // Handle Authentication Failure
  private handleAuthFailure(): void {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
    
    // Dispatch custom event for auth failure
    window.dispatchEvent(new CustomEvent('token-expired'));
    
    console.warn('⚠️ Authentication failed, redirecting to login');
  }

  // Set Auth Token
  public setAuthToken(token: string): void {
    this.api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  // Clear Auth Token
  public clearAuthToken(): void {
    delete this.api.defaults.headers.common['Authorization'];
  }

  // Login
  public async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const response: AxiosResponse<ApiResponse<AuthResponse>> = await this.api.post(
        '/auth/login',
        credentials
      );

      const authData = response.data.data;
      
      // Store tokens
      localStorage.setItem(TOKEN_STORAGE_KEY, authData.token);
      localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, authData.refreshToken);
      
      // Set auth header
      this.setAuthToken(authData.token);
      
      return authData;
    } catch (error: any) {
      console.error('❌ Login error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Register
  public async register(data: RegisterData): Promise<AuthResponse> {
    try {
      const response: AxiosResponse<ApiResponse<AuthResponse>> = await this.api.post(
        '/auth/register',
        data
      );

      const authData = response.data.data;
      
      // Store tokens
      localStorage.setItem(TOKEN_STORAGE_KEY, authData.token);
      localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, authData.refreshToken);
      
      // Set auth header
      this.setAuthToken(authData.token);
      
      return authData;
    } catch (error: any) {
      console.error('❌ Register error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Logout
  public async logout(): Promise<void> {
    try {
      await this.api.post('/auth/logout');
    } catch (error) {
      console.warn('⚠️ Logout API call failed:', error);
    } finally {
      // Clear local storage and headers regardless of API call result
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
      this.clearAuthToken();
    }
  }

  // Refresh Token
  public async refreshToken(): Promise<AuthResponse> {
    const refreshToken = localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response: AxiosResponse<ApiResponse<RefreshTokenResponse>> = await this.api.post(
        '/auth/refresh',
        { refreshToken }
      );

      const tokenData = response.data.data;
      
      // Store new tokens
      localStorage.setItem(TOKEN_STORAGE_KEY, tokenData.token);
      localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, tokenData.refreshToken);
      
      // Set auth header
      this.setAuthToken(tokenData.token);
      
      // Get current user info
      const user = await this.getCurrentUser();
      
      return {
        user,
        token: tokenData.token,
        refreshToken: tokenData.refreshToken,
        expiresIn: tokenData.expiresIn,
        tokenType: 'Bearer',
      };
    } catch (error: any) {
      console.error('❌ Token refresh error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Current User
  public async getCurrentUser(): Promise<User> {
    try {
      const response: AxiosResponse<ApiResponse<UserProfileResponse>> = await this.api.get(
        '/auth/me'
      );

      return response.data.data.user;
    } catch (error: any) {
      console.error('❌ Get current user error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Update Profile
  public async updateProfile(data: UpdateProfileData): Promise<User> {
    try {
      const response: AxiosResponse<ApiResponse<UserProfileResponse>> = await this.api.put(
        '/auth/profile',
        data
      );

      return response.data.data.user;
    } catch (error: any) {
      console.error('❌ Update profile error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Change Password
  public async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    try {
      const data: ChangePasswordData = {
        currentPassword,
        newPassword,
        confirmPassword: newPassword,
      };

      await this.api.put('/auth/change-password', data);
    } catch (error: any) {
      console.error('❌ Change password error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Request Password Reset
  public async requestPasswordReset(email: string): Promise<void> {
    try {
      const data: PasswordResetRequest = { email };
      await this.api.post('/auth/password-reset', data);
    } catch (error: any) {
      console.error('❌ Password reset request error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Confirm Password Reset
  public async confirmPasswordReset(data: PasswordResetConfirm): Promise<void> {
    try {
      await this.api.post('/auth/password-reset/confirm', data);
    } catch (error: any) {
      console.error('❌ Password reset confirm error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Verify Email
  public async verifyEmail(token: string): Promise<void> {
    try {
      const data: EmailVerificationData = { token };
      await this.api.post('/auth/verify-email', data);
    } catch (error: any) {
      console.error('❌ Email verification error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Resend Email Verification
  public async resendEmailVerification(): Promise<void> {
    try {
      await this.api.post('/auth/verify-email/resend');
    } catch (error: any) {
      console.error('❌ Resend email verification error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Setup Two Factor Authentication
  public async setupTwoFactor(): Promise<TwoFactorSetupData> {
    try {
      const response: AxiosResponse<ApiResponse<TwoFactorSetupData>> = await this.api.post(
        '/auth/2fa/setup'
      );

      return response.data.data;
    } catch (error: any) {
      console.error('❌ 2FA setup error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Verify Two Factor Authentication
  public async verifyTwoFactor(code: string): Promise<void> {
    try {
      const data: TwoFactorVerifyData = { code };
      await this.api.post('/auth/2fa/verify', data);
    } catch (error: any) {
      console.error('❌ 2FA verification error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Disable Two Factor Authentication
  public async disableTwoFactor(password: string): Promise<void> {
    try {
      await this.api.post('/auth/2fa/disable', { password });
    } catch (error: any) {
      console.error('❌ 2FA disable error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Account Security Info
  public async getAccountSecurity(): Promise<AccountSecurity> {
    try {
      const response: AxiosResponse<ApiResponse<SecuritySettingsResponse>> = await this.api.get(
        '/auth/security'
      );

      return response.data.data.security;
    } catch (error: any) {
      console.error('❌ Get security info error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get Active Sessions
  public async getActiveSessions(): Promise<SessionInfo[]> {
    try {
      const response: AxiosResponse<ApiResponse<SessionInfo[]>> = await this.api.get(
        '/auth/sessions'
      );

      return response.data.data;
    } catch (error: any) {
      console.error('❌ Get sessions error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Revoke Session
  public async revokeSession(sessionId: string): Promise<void> {
    try {
      await this.api.delete(`/auth/sessions/${sessionId}`);
    } catch (error: any) {
      console.error('❌ Revoke session error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Revoke All Sessions
  public async revokeAllSessions(): Promise<void> {
    try {
      await this.api.delete('/auth/sessions');
    } catch (error: any) {
      console.error('❌ Revoke all sessions error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Upload Avatar
  public async uploadAvatar(file: File): Promise<string> {
    try {
      const formData = new FormData();
      formData.append('avatar', file);

      const response: AxiosResponse<ApiResponse<{ url: string }>> = await this.api.post(
        '/auth/avatar',
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      return response.data.data.url;
    } catch (error: any) {
      console.error('❌ Avatar upload error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Delete Avatar
  public async deleteAvatar(): Promise<void> {
    try {
      await this.api.delete('/auth/avatar');
    } catch (error: any) {
      console.error('❌ Avatar delete error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Check if user is authenticated
  public isAuthenticated(): boolean {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    return token !== null && !isTokenExpired(token);
  }

  // Get stored token
  public getToken(): string | null {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  }

  // Get stored refresh token
  public getRefreshToken(): string | null {
    return localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
  }

  // Clear all auth data
  public clearAuthData(): void {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
    this.clearAuthToken();
  }
}

// Create and export singleton instance
export const authService = new AuthService();

// Export default
export default authService;