import axios, { AxiosInstance, AxiosResponse, AxiosRequestConfig } from 'axios';
import {
  ApiResponse,
  PaginatedResponse,
  QueryParams,
  Target,
  Scan,
  Vulnerability,
  Report,
  DashboardStats,
  Notification,
  SystemInfo,
  SearchRequest,
  SearchResponse,
  ExportRequest,
  ImportRequest,
  ImportResult,
} from '../types/api';

// API Base URL
const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:8000/api';

// Request timeout
const DEFAULT_TIMEOUT = 30000;

// API Service Class
export class ApiService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: API_BASE_URL,
      timeout: DEFAULT_TIMEOUT,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  // Setup Axios Interceptors
  private setupInterceptors(): void {
    // Request Interceptor - Add auth token and request ID
    this.api.interceptors.request.use(
      (config) => {
        // Add auth token
        const token = localStorage.getItem('nexus_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Add request ID for tracking
        config.headers['X-Request-ID'] = this.generateRequestId();

        // Add timestamp
        config.headers['X-Request-Time'] = new Date().toISOString();

        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response Interceptor - Handle common errors
    this.api.interceptors.response.use(
      (response) => {
        // Log successful requests in development
        if (process.env['NODE_ENV'] === 'development') {
          console.log(`✅ ${response.config.method?.toUpperCase()} ${response.config.url}`, {
            status: response.status,
            data: response.data,
          });
        }
        return response;
      },
      (error) => {
        // Log errors
        console.error(`❌ API Error:`, {
          url: error.config?.url,
          method: error.config?.method,
          status: error.response?.status,
          data: error.response?.data,
        });

        // Handle specific error cases
        if (error.response?.status === 401) {
          // Token expired, dispatch event
          window.dispatchEvent(new CustomEvent('token-expired'));
        } else if (error.response?.status === 403) {
          // Forbidden, show permission error
          console.warn('⚠️ Insufficient permissions for this action');
        } else if (error.response?.status >= 500) {
          // Server error, show generic error
          console.error('🔥 Server error occurred');
        }

        return Promise.reject(error);
      }
    );
  }

  // Generate unique request ID
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Build query string from params
  private buildQueryString(params: QueryParams): string {
    const searchParams = new URLSearchParams();

    if (params.page) searchParams.append('page', params.page.toString());
    if (params.limit) searchParams.append('limit', params.limit.toString());
    if (params.sort) searchParams.append('sort', params.sort);
    if (params.order) searchParams.append('order', params.order);
    if (params.search) searchParams.append('search', params.search);
    
    if (params.filter) {
      Object.entries(params.filter).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          searchParams.append(`filter[${key}]`, value.toString());
        }
      });
    }
    
    if (params.include) {
      params.include.forEach(field => searchParams.append('include[]', field));
    }
    
    if (params.fields) {
      params.fields.forEach(field => searchParams.append('fields[]', field));
    }

    return searchParams.toString();
  }

  // Generic GET request
  public async get<T>(url: string, params?: QueryParams, config?: AxiosRequestConfig): Promise<T> {
    const queryString = params ? this.buildQueryString(params) : '';
    const fullUrl = queryString ? `${url}?${queryString}` : url;
    
    const response: AxiosResponse<ApiResponse<T>> = await this.api.get(fullUrl, config);
    return response.data.data;
  }

  // Generic POST request
  public async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<ApiResponse<T>> = await this.api.post(url, data, config);
    return response.data.data;
  }

  // Generic PUT request
  public async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<ApiResponse<T>> = await this.api.put(url, data, config);
    return response.data.data;
  }

  // Generic PATCH request
  public async patch<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<ApiResponse<T>> = await this.api.patch(url, data, config);
    return response.data.data;
  }

  // Generic DELETE request
  public async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<ApiResponse<T>> = await this.api.delete(url, config);
    return response.data.data;
  }

  // Generic paginated GET request
  public async getPaginated<T>(url: string, params?: QueryParams, config?: AxiosRequestConfig): Promise<PaginatedResponse<T>> {
    const queryString = params ? this.buildQueryString(params) : '';
    const fullUrl = queryString ? `${url}?${queryString}` : url;
    
    const response: AxiosResponse<PaginatedResponse<T>> = await this.api.get(fullUrl, config);
    return response.data;
  }

  // ===================
  // TARGET ENDPOINTS
  // ===================

  // Get all targets
  public async getTargets(params?: QueryParams): Promise<PaginatedResponse<Target>> {
    return this.getPaginated<Target>('/targets', params);
  }

  // Get target by ID
  public async getTarget(id: number): Promise<Target> {
    return this.get<Target>(`/targets/${id}`);
  }

  // Create new target
  public async createTarget(data: Partial<Target>): Promise<Target> {
    return this.post<Target>('/targets', data);
  }

  // Update target
  public async updateTarget(id: number, data: Partial<Target>): Promise<Target> {
    return this.put<Target>(`/targets/${id}`, data);
  }

  // Delete target
  public async deleteTarget(id: number): Promise<void> {
    return this.delete<void>(`/targets/${id}`);
  }

  // Bulk delete targets
  public async deleteTargets(ids: number[]): Promise<void> {
    return this.post<void>('/targets/bulk-delete', { ids });
  }

  // Validate target URL
  public async validateTarget(url: string): Promise<{ valid: boolean; message?: string }> {
    return this.post<{ valid: boolean; message?: string }>('/targets/validate', { url });
  }

  // ===================
  // SCAN ENDPOINTS
  // ===================

  // Get all scans
  public async getScans(params?: QueryParams): Promise<PaginatedResponse<Scan>> {
    return this.getPaginated<Scan>('/scans', params);
  }

  // Get scan by ID
  public async getScan(id: number): Promise<Scan> {
    return this.get<Scan>(`/scans/${id}`);
  }

  // Create new scan
  public async createScan(data: Partial<Scan>): Promise<Scan> {
    return this.post<Scan>('/scans', data);
  }

  // Start scan
  public async startScan(id: number): Promise<Scan> {
    return this.post<Scan>(`/scans/${id}/start`);
  }

  // Stop scan
  public async stopScan(id: number): Promise<Scan> {
    return this.post<Scan>(`/scans/${id}/stop`);
  }

  // Pause scan
  public async pauseScan(id: number): Promise<Scan> {
    return this.post<Scan>(`/scans/${id}/pause`);
  }

  // Resume scan
  public async resumeScan(id: number): Promise<Scan> {
    return this.post<Scan>(`/scans/${id}/resume`);
  }

  // Delete scan
  public async deleteScan(id: number): Promise<void> {
    return this.delete<void>(`/scans/${id}`);
  }

  // Get scan results
  public async getScanResults(id: number): Promise<any> {
    return this.get<any>(`/scans/${id}/results`);
  }

  // Get scan logs
  public async getScanLogs(id: number, params?: QueryParams): Promise<PaginatedResponse<any>> {
    return this.getPaginated<any>(`/scans/${id}/logs`, params);
  }

  // ===================
  // VULNERABILITY ENDPOINTS
  // ===================

  // Get all vulnerabilities
  public async getVulnerabilities(params?: QueryParams): Promise<PaginatedResponse<Vulnerability>> {
    return this.getPaginated<Vulnerability>('/vulnerabilities', params);
  }

  // Get vulnerability by ID
  public async getVulnerability(id: number): Promise<Vulnerability> {
    return this.get<Vulnerability>(`/vulnerabilities/${id}`);
  }

  // Update vulnerability status
  public async updateVulnerabilityStatus(id: number, status: string): Promise<Vulnerability> {
    return this.patch<Vulnerability>(`/vulnerabilities/${id}`, { status });
  }

  // Mark vulnerability as false positive
  public async markAsFalsePositive(id: number, reason?: string): Promise<Vulnerability> {
    return this.patch<Vulnerability>(`/vulnerabilities/${id}`, { 
      falsePositive: true,
      reason 
    });
  }

  // Verify vulnerability
  public async verifyVulnerability(id: number): Promise<Vulnerability> {
    return this.patch<Vulnerability>(`/vulnerabilities/${id}`, { verified: true });
  }

  // ===================
  // REPORT ENDPOINTS
  // ===================

  // Get all reports
  public async getReports(params?: QueryParams): Promise<PaginatedResponse<Report>> {
    return this.getPaginated<Report>('/reports', params);
  }

  // Get report by ID
  public async getReport(id: number): Promise<Report> {
    return this.get<Report>(`/reports/${id}`);
  }

  // Generate report
  public async generateReport(data: Partial<Report>): Promise<Report> {
    return this.post<Report>('/reports', data);
  }

  // Download report
  public async downloadReport(id: number): Promise<Blob> {
    const response: AxiosResponse<Blob> = await this.api.get(`/reports/${id}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  // Delete report
  public async deleteReport(id: number): Promise<void> {
    return this.delete<void>(`/reports/${id}`);
  }

  // ===================
  // DASHBOARD ENDPOINTS
  // ===================

  // Get dashboard statistics
  public async getDashboardStats(): Promise<DashboardStats> {
    return this.get<DashboardStats>('/dashboard/stats');
  }

  // Get recent activity
  public async getRecentActivity(limit?: number): Promise<any[]> {
    const params = limit !== undefined ? { limit } : {};
    return this.get<any[]>('/dashboard/activity', params);
  }

  // ===================
  // NOTIFICATION ENDPOINTS
  // ===================

  // Get notifications
  public async getNotifications(params?: QueryParams): Promise<PaginatedResponse<Notification>> {
    return this.getPaginated<Notification>('/notifications', params);
  }

  // Mark notification as read
  public async markNotificationAsRead(id: number): Promise<Notification> {
    return this.patch<Notification>(`/notifications/${id}`, { read: true });
  }

  // Mark all notifications as read
  public async markAllNotificationsAsRead(): Promise<void> {
    return this.post<void>('/notifications/mark-all-read');
  }

  // Delete notification
  public async deleteNotification(id: number): Promise<void> {
    return this.delete<void>(`/notifications/${id}`);
  }

  // ===================
  // SEARCH ENDPOINTS
  // ===================

  // Global search
  public async search(request: SearchRequest): Promise<SearchResponse> {
    return this.post<SearchResponse>('/search', request);
  }

  // Search suggestions
  public async getSearchSuggestions(query: string): Promise<string[]> {
    return this.get<string[]>('/search/suggestions', { search: query });
  }

  // ===================
  // EXPORT/IMPORT ENDPOINTS
  // ===================

  // Export data
  public async exportData(request: ExportRequest): Promise<Blob> {
    const response: AxiosResponse<Blob> = await this.api.post('/export', request, {
      responseType: 'blob',
    });
    return response.data;
  }

  // Import data
  public async importData(request: ImportRequest): Promise<ImportResult> {
    const formData = new FormData();
    formData.append('file', request.file);
    formData.append('type', request.type);
    formData.append('format', request.format);
    
    if (request.options) {
      formData.append('options', JSON.stringify(request.options));
    }

    return this.post<ImportResult>('/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  }

  // ===================
  // SYSTEM ENDPOINTS
  // ===================

  // Get system information
  public async getSystemInfo(): Promise<SystemInfo> {
    return this.get<SystemInfo>('/system/info');
  }

  // Health check
  public async healthCheck(): Promise<{ status: string; timestamp: string }> {
    return this.get<{ status: string; timestamp: string }>('/system/health');
  }

  // ===================
  // FILE UPLOAD ENDPOINTS
  // ===================

  // Upload file
  public async uploadFile(
    file: File,
    onProgress?: (progress: number) => void
  ): Promise<{ url: string; filename: string }> {
    const formData = new FormData();
    formData.append('file', file);

    return this.post<{ url: string; filename: string }>('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(progress);
        }
      },
    });
  }

  // Delete uploaded file
  public async deleteFile(filename: string): Promise<void> {
    return this.delete<void>(`/upload/${filename}`);
  }

  // ===================
  // UTILITY METHODS
  // ===================

  // Cancel request
  public cancelRequest(requestId: string): void {
    // Implementation for request cancellation
    console.log(`Cancelling request: ${requestId}`);
  }

  // Set timeout for specific request
  public setRequestTimeout(timeout: number): void {
    this.api.defaults.timeout = timeout;
  }

  // Reset timeout to default
  public resetRequestTimeout(): void {
    this.api.defaults.timeout = DEFAULT_TIMEOUT;
  }

  // Get API base URL
  public getBaseURL(): string {
    return API_BASE_URL;
  }

  // Check if API is available
  public async isApiAvailable(): Promise<boolean> {
    try {
      await this.healthCheck();
      return true;
    } catch {
      return false;
    }
  }

  // Get request statistics
  public getRequestStats(): {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
  } {
    // This would need to be implemented with proper tracking
    return {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
    };
  }
}

// Create and export singleton instance
export const apiService = new ApiService();

// Export default
export default apiService;