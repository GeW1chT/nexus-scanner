import React, { createContext, useContext, useReducer, useEffect, useCallback, ReactNode } from 'react';
import { authService } from '../services/authService';
import { User, LoginCredentials, RegisterData } from '../types/auth';

// Auth State Interface
interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  token: string | null;
}

// Auth Actions
type AuthAction =
  | { type: 'AUTH_START' }
  | { type: 'AUTH_SUCCESS'; payload: { user: User; token: string } }
  | { type: 'AUTH_FAILURE'; payload: string }
  | { type: 'AUTH_LOGOUT' }
  | { type: 'AUTH_CLEAR_ERROR' }
  | { type: 'AUTH_UPDATE_USER'; payload: User }
  | { type: 'AUTH_SET_LOADING'; payload: boolean };

// Auth Context Interface
interface AuthContextType {
  // State
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  token: string | null;
  
  // Actions
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  clearError: () => void;
  checkAuthStatus: () => Promise<void>;
}

// Initial State
const initialState: AuthState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
  token: localStorage.getItem('nexus_token'),
};

// Auth Reducer
function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'AUTH_START':
      return {
        ...state,
        isLoading: true,
        error: null,
      };
      
    case 'AUTH_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };
      
    case 'AUTH_FAILURE':
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload,
      };
      
    case 'AUTH_LOGOUT':
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      };
      
    case 'AUTH_CLEAR_ERROR':
      return {
        ...state,
        error: null,
      };
      
    case 'AUTH_UPDATE_USER':
      return {
        ...state,
        user: action.payload,
      };
      
    case 'AUTH_SET_LOADING':
      return {
        ...state,
        isLoading: action.payload,
      };
      
    default:
      return state;
  }
}

// Create Context
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Auth Provider Props
interface AuthProviderProps {
  children: ReactNode;
}

// Auth Provider Component
export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Login Function
  const login = async (credentials: LoginCredentials): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      const response = await authService.login(credentials);
      
      // Store token in localStorage
      localStorage.setItem('nexus_token', response.token);
      
      // Update axios default headers
      authService.setAuthToken(response.token);
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: {
          user: response.user,
          token: response.token,
        },
      });
      
      // Log successful login
      console.log('✅ Kullanıcı başarıyla giriş yaptı:', response.user.email);
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Giriş yapılırken hata oluştu';
      
      dispatch({
        type: 'AUTH_FAILURE',
        payload: errorMessage,
      });
      
      // Remove invalid token
      localStorage.removeItem('nexus_token');
      authService.clearAuthToken();
      
      console.error('❌ Giriş hatası:', errorMessage);
      throw error;
    }
  };

  // Register Function
  const register = async (data: RegisterData): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      const response = await authService.register(data);
      
      // Store token in localStorage
      localStorage.setItem('nexus_token', response.token);
      
      // Update axios default headers
      authService.setAuthToken(response.token);
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: {
          user: response.user,
          token: response.token,
        },
      });
      
      console.log('✅ Kullanıcı başarıyla kayıt oldu:', response.user.email);
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Kayıt olurken hata oluştu';
      
      dispatch({
        type: 'AUTH_FAILURE',
        payload: errorMessage,
      });
      
      console.error('❌ Kayıt hatası:', errorMessage);
      throw error;
    }
  };

  // Logout Function
  const logout = useCallback(async (): Promise<void> => {
    try {
      // Call logout endpoint if token exists
      if (state.token) {
        await authService.logout();
      }
    } catch (error) {
      console.warn('⚠️ Logout endpoint hatası:', error);
    } finally {
      // Clear local storage and state regardless of API call result
      localStorage.removeItem('nexus_token');
      authService.clearAuthToken();
      
      dispatch({ type: 'AUTH_LOGOUT' });
      
      console.log('✅ Kullanıcı çıkış yaptı');
    }
  }, [state.token]);

  // Refresh Token Function
  const refreshToken = useCallback(async (): Promise<void> => {
    try {
      const response = await authService.refreshToken();
      
      // Update token in localStorage
      localStorage.setItem('nexus_token', response.token);
      
      // Update axios default headers
      authService.setAuthToken(response.token);
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: {
          user: response.user,
          token: response.token,
        },
      });
      
      console.log('✅ Token yenilendi');
      
    } catch (error: any) {
      console.error('❌ Token yenileme hatası:', error);
      
      // If refresh fails, logout user
      await logout();
      throw error;
    }
  }, [logout]);

  // Update Profile Function
  const updateProfile = async (data: Partial<User>): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      const updatedUser = await authService.updateProfile(data);
      
      dispatch({
        type: 'AUTH_UPDATE_USER',
        payload: updatedUser,
      });
      
      console.log('✅ Profil güncellendi');
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Profil güncellenirken hata oluştu';
      
      dispatch({
        type: 'AUTH_FAILURE',
        payload: errorMessage,
      });
      
      console.error('❌ Profil güncelleme hatası:', errorMessage);
      throw error;
    } finally {
      dispatch({ type: 'AUTH_SET_LOADING', payload: false });
    }
  };

  // Change Password Function
  const changePassword = async (currentPassword: string, newPassword: string): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      await authService.changePassword(currentPassword, newPassword);
      
      console.log('✅ Şifre değiştirildi');
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Şifre değiştirilirken hata oluştu';
      
      dispatch({
        type: 'AUTH_FAILURE',
        payload: errorMessage,
      });
      
      console.error('❌ Şifre değiştirme hatası:', errorMessage);
      throw error;
    } finally {
      dispatch({ type: 'AUTH_SET_LOADING', payload: false });
    }
  };

  // Clear Error Function
  const clearError = (): void => {
    dispatch({ type: 'AUTH_CLEAR_ERROR' });
  };

  // Check Auth Status Function
  const checkAuthStatus = useCallback(async (): Promise<void> => {
    const token = localStorage.getItem('nexus_token');
    
    if (!token) {
      dispatch({ type: 'AUTH_SET_LOADING', payload: false });
      return;
    }
    
    try {
      // Set token in axios headers
      authService.setAuthToken(token);
      
      // Verify token with backend
      const user = await authService.getCurrentUser();
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: {
          user,
          token,
        },
      });
      
      console.log('✅ Auth durumu doğrulandı:', user.email);
      
    } catch (error: any) {
      console.warn('⚠️ Token doğrulama hatası:', error.message);
      
      // Clear invalid token
      localStorage.removeItem('nexus_token');
      authService.clearAuthToken();
      
      dispatch({ type: 'AUTH_LOGOUT' });
    }
  }, []);

  // Auto-refresh token before expiration
  useEffect(() => {
    let refreshInterval: NodeJS.Timeout;
    
    if (state.isAuthenticated && state.token) {
      // Refresh token every 50 minutes (assuming 1 hour expiration)
      refreshInterval = setInterval(() => {
        refreshToken().catch((error) => {
          console.error('❌ Otomatik token yenileme hatası:', error);
        });
      }, 50 * 60 * 1000);
    }
    
    return () => {
      if (refreshInterval) {
        clearInterval(refreshInterval);
      }
    };
  }, [state.isAuthenticated, state.token, refreshToken]);

  // Check auth status on mount
  useEffect(() => {
    checkAuthStatus();
  }, [checkAuthStatus]);

  // Handle token expiration
  useEffect(() => {
    const handleTokenExpiration = () => {
      console.warn('⚠️ Token süresi doldu, kullanıcı çıkış yapılıyor');
      logout();
    };
    
    // Listen for 401 responses from axios interceptor
    window.addEventListener('token-expired', handleTokenExpiration);
    
    return () => {
      window.removeEventListener('token-expired', handleTokenExpiration);
    };
  }, [logout]);

  // Context value
  const contextValue: AuthContextType = {
    // State
    user: state.user,
    isAuthenticated: state.isAuthenticated,
    isLoading: state.isLoading,
    error: state.error,
    token: state.token,
    
    // Actions
    login,
    register,
    logout,
    refreshToken,
    updateProfile,
    changePassword,
    clearError,
    checkAuthStatus,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use auth context
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
};

// Export context for testing
export { AuthContext };

// Export types
export type { AuthState, AuthAction, AuthContextType };