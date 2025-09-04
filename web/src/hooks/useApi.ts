import { useQuery, useMutation, useQueryClient, UseQueryOptions, UseMutationOptions } from '@tanstack/react-query';
import { useCallback } from 'react';
import {
  Target,
  Scan,
  Vulnerability,
  Report,
  DashboardStats,
  Notification,
  QueryParams,
  PaginatedResponse,
  SearchRequest,
  SearchResponse,
  ExportRequest,
  ImportRequest,
  ImportResult,
} from '../types/api';
import { apiService } from '../services/apiService';

// Query Keys
export const queryKeys = {
  // Targets
  targets: ['targets'] as const,
  target: (id: number) => ['targets', id] as const,
  targetValidation: (url: string) => ['targets', 'validation', url] as const,
  
  // Scans
  scans: ['scans'] as const,
  scan: (id: number) => ['scans', id] as const,
  scanResults: (id: number) => ['scans', id, 'results'] as const,
  scanLogs: (id: number) => ['scans', id, 'logs'] as const,
  
  // Vulnerabilities
  vulnerabilities: ['vulnerabilities'] as const,
  vulnerability: (id: number) => ['vulnerabilities', id] as const,
  
  // Reports
  reports: ['reports'] as const,
  report: (id: number) => ['reports', id] as const,
  
  // Dashboard
  dashboardStats: ['dashboard', 'stats'] as const,
  recentActivity: ['dashboard', 'activity'] as const,
  
  // Notifications
  notifications: ['notifications'] as const,
  
  // Search
  search: (query: string) => ['search', query] as const,
  searchSuggestions: (query: string) => ['search', 'suggestions', query] as const,
  
  // System
  systemInfo: ['system', 'info'] as const,
  healthCheck: ['system', 'health'] as const,
} as const;

// ===================
// TARGET HOOKS
// ===================

// Get targets with pagination
export const useTargets = (
  params?: QueryParams,
  options?: UseQueryOptions<PaginatedResponse<Target>>
) => {
  return useQuery({
    queryKey: [...queryKeys.targets, params],
    queryFn: () => apiService.getTargets(params),
    staleTime: 5 * 60 * 1000, // 5 minutes
    ...options,
  });
};

// Get single target
export const useTarget = (
  id: number,
  options?: UseQueryOptions<Target>
) => {
  return useQuery({
    queryKey: queryKeys.target(id),
    queryFn: () => apiService.getTarget(id),
    enabled: !!id,
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Create target mutation
export const useCreateTarget = (
  options?: UseMutationOptions<Target, Error, Partial<Target>>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: Partial<Target>) => apiService.createTarget(data),
    onSuccess: (newTarget) => {
      // Invalidate targets list
      queryClient.invalidateQueries({ queryKey: queryKeys.targets });
      
      // Add to cache
      queryClient.setQueryData(queryKeys.target(newTarget.id), newTarget);
    },
    ...options,
  });
};

// Update target mutation
export const useUpdateTarget = (
  options?: UseMutationOptions<Target, Error, { id: number; data: Partial<Target> }>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ id, data }) => apiService.updateTarget(id, data),
    onSuccess: (updatedTarget) => {
      // Update cache
      queryClient.setQueryData(queryKeys.target(updatedTarget.id), updatedTarget);
      
      // Invalidate targets list
      queryClient.invalidateQueries({ queryKey: queryKeys.targets });
    },
    ...options,
  });
};

// Delete target mutation
export const useDeleteTarget = (
  options?: UseMutationOptions<void, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.deleteTarget(id),
    onSuccess: (_, id) => {
      // Remove from cache
      queryClient.removeQueries({ queryKey: queryKeys.target(id) });
      
      // Invalidate targets list
      queryClient.invalidateQueries({ queryKey: queryKeys.targets });
    },
    ...options,
  });
};

// Bulk delete targets mutation
export const useBulkDeleteTargets = (
  options?: UseMutationOptions<void, Error, number[]>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (ids: number[]) => apiService.deleteTargets(ids),
    onSuccess: (_, ids) => {
      // Remove from cache
      ids.forEach(id => {
        queryClient.removeQueries({ queryKey: queryKeys.target(id) });
      });
      
      // Invalidate targets list
      queryClient.invalidateQueries({ queryKey: queryKeys.targets });
    },
    ...options,
  });
};

// Validate target URL
export const useValidateTarget = (
  url: string,
  options?: UseQueryOptions<{ valid: boolean; message?: string }>
) => {
  return useQuery({
    queryKey: queryKeys.targetValidation(url),
    queryFn: () => apiService.validateTarget(url),
    enabled: !!url && url.length > 0,
    staleTime: 10 * 60 * 1000, // 10 minutes
    ...options,
  });
};

// ===================
// SCAN HOOKS
// ===================

// Get scans with pagination
export const useScans = (
  params?: QueryParams,
  options?: UseQueryOptions<PaginatedResponse<Scan>>
) => {
  return useQuery({
    queryKey: [...queryKeys.scans, params],
    queryFn: () => apiService.getScans(params),
    staleTime: 2 * 60 * 1000, // 2 minutes
    refetchInterval: 30000, // Refetch every 30 seconds for active scans
    ...options,
  });
};

// Get single scan
export const useScan = (
  id: number,
  options?: UseQueryOptions<Scan>
) => {
  return useQuery({
    queryKey: queryKeys.scan(id),
    queryFn: () => apiService.getScan(id),
    enabled: !!id,
    staleTime: 1 * 60 * 1000, // 1 minute
    refetchInterval: (query) => {
      // Refetch more frequently for running scans
      return query.state.data?.status === 'running' ? 5000 : 30000;
    },
    ...options,
  });
};

// Create scan mutation
export const useCreateScan = (
  options?: UseMutationOptions<Scan, Error, Partial<Scan>>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: Partial<Scan>) => apiService.createScan(data),
    onSuccess: (newScan) => {
      // Invalidate scans list
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
      
      // Add to cache
      queryClient.setQueryData(queryKeys.scan(newScan.id), newScan);
    },
    ...options,
  });
};

// Start scan mutation
export const useStartScan = (
  options?: UseMutationOptions<Scan, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.startScan(id),
    onSuccess: (updatedScan) => {
      // Update cache
      queryClient.setQueryData(queryKeys.scan(updatedScan.id), updatedScan);
      
      // Invalidate scans list
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
    },
    ...options,
  });
};

// Stop scan mutation
export const useStopScan = (
  options?: UseMutationOptions<Scan, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.stopScan(id),
    onSuccess: (updatedScan) => {
      // Update cache
      queryClient.setQueryData(queryKeys.scan(updatedScan.id), updatedScan);
      
      // Invalidate scans list
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
    },
    ...options,
  });
};

// Pause scan mutation
export const usePauseScan = (
  options?: UseMutationOptions<Scan, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.pauseScan(id),
    onSuccess: (updatedScan) => {
      queryClient.setQueryData(queryKeys.scan(updatedScan.id), updatedScan);
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
    },
    ...options,
  });
};

// Resume scan mutation
export const useResumeScan = (
  options?: UseMutationOptions<Scan, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.resumeScan(id),
    onSuccess: (updatedScan) => {
      queryClient.setQueryData(queryKeys.scan(updatedScan.id), updatedScan);
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
    },
    ...options,
  });
};

// Delete scan mutation
export const useDeleteScan = (
  options?: UseMutationOptions<void, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.deleteScan(id),
    onSuccess: (_, id) => {
      // Remove from cache
      queryClient.removeQueries({ queryKey: queryKeys.scan(id) });
      queryClient.removeQueries({ queryKey: queryKeys.scanResults(id) });
      queryClient.removeQueries({ queryKey: queryKeys.scanLogs(id) });
      
      // Invalidate scans list
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
    },
    ...options,
  });
};

// Get scan results
export const useScanResults = (
  id: number,
  options?: UseQueryOptions<any>
) => {
  return useQuery({
    queryKey: queryKeys.scanResults(id),
    queryFn: () => apiService.getScanResults(id),
    enabled: !!id,
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Get scan logs
export const useScanLogs = (
  id: number,
  params?: QueryParams,
  options?: UseQueryOptions<PaginatedResponse<any>>
) => {
  return useQuery({
    queryKey: [...queryKeys.scanLogs(id), params],
    queryFn: () => apiService.getScanLogs(id, params),
    enabled: !!id,
    staleTime: 1 * 60 * 1000,
    ...options,
  });
};

// ===================
// VULNERABILITY HOOKS
// ===================

// Get vulnerabilities with pagination
export const useVulnerabilities = (
  params?: QueryParams,
  options?: UseQueryOptions<PaginatedResponse<Vulnerability>>
) => {
  return useQuery({
    queryKey: [...queryKeys.vulnerabilities, params],
    queryFn: () => apiService.getVulnerabilities(params),
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Get single vulnerability
export const useVulnerability = (
  id: number,
  options?: UseQueryOptions<Vulnerability>
) => {
  return useQuery({
    queryKey: queryKeys.vulnerability(id),
    queryFn: () => apiService.getVulnerability(id),
    enabled: !!id,
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Update vulnerability status mutation
export const useUpdateVulnerabilityStatus = (
  options?: UseMutationOptions<Vulnerability, Error, { id: number; status: string }>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ id, status }) => apiService.updateVulnerabilityStatus(id, status),
    onSuccess: (updatedVulnerability) => {
      // Update cache
      queryClient.setQueryData(queryKeys.vulnerability(updatedVulnerability.id), updatedVulnerability);
      
      // Invalidate vulnerabilities list
      queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
    },
    ...options,
  });
};

// Mark as false positive mutation
export const useMarkAsFalsePositive = (
  options?: UseMutationOptions<Vulnerability, Error, { id: number; reason?: string }>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ id, reason }) => apiService.markAsFalsePositive(id, reason),
    onSuccess: (updatedVulnerability) => {
      queryClient.setQueryData(queryKeys.vulnerability(updatedVulnerability.id), updatedVulnerability);
      queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
    },
    ...options,
  });
};

// Verify vulnerability mutation
export const useVerifyVulnerability = (
  options?: UseMutationOptions<Vulnerability, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.verifyVulnerability(id),
    onSuccess: (updatedVulnerability) => {
      queryClient.setQueryData(queryKeys.vulnerability(updatedVulnerability.id), updatedVulnerability);
      queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
    },
    ...options,
  });
};

// ===================
// REPORT HOOKS
// ===================

// Get reports with pagination
export const useReports = (
  params?: QueryParams,
  options?: UseQueryOptions<PaginatedResponse<Report>>
) => {
  return useQuery({
    queryKey: [...queryKeys.reports, params],
    queryFn: () => apiService.getReports(params),
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Get single report
export const useReport = (
  id: number,
  options?: UseQueryOptions<Report>
) => {
  return useQuery({
    queryKey: queryKeys.report(id),
    queryFn: () => apiService.getReport(id),
    enabled: !!id,
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Generate report mutation
export const useGenerateReport = (
  options?: UseMutationOptions<Report, Error, Partial<Report>>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: Partial<Report>) => apiService.generateReport(data),
    onSuccess: (newReport) => {
      // Invalidate reports list
      queryClient.invalidateQueries({ queryKey: queryKeys.reports });
      
      // Add to cache
      queryClient.setQueryData(queryKeys.report(newReport.id), newReport);
    },
    ...options,
  });
};

// Download report mutation
export const useDownloadReport = (
  options?: UseMutationOptions<Blob, Error, number>
) => {
  return useMutation({
    mutationFn: (id: number) => apiService.downloadReport(id),
    ...options,
  });
};

// Delete report mutation
export const useDeleteReport = (
  options?: UseMutationOptions<void, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.deleteReport(id),
    onSuccess: (_, id) => {
      // Remove from cache
      queryClient.removeQueries({ queryKey: queryKeys.report(id) });
      
      // Invalidate reports list
      queryClient.invalidateQueries({ queryKey: queryKeys.reports });
    },
    ...options,
  });
};

// ===================
// DASHBOARD HOOKS
// ===================

// Get dashboard statistics
export const useDashboardStats = (
  options?: UseQueryOptions<DashboardStats>
) => {
  return useQuery({
    queryKey: queryKeys.dashboardStats,
    queryFn: () => apiService.getDashboardStats(),
    staleTime: 2 * 60 * 1000, // 2 minutes
    refetchInterval: 60000, // Refetch every minute
    ...options,
  });
};

// Get recent activity
export const useRecentActivity = (
  limit?: number,
  options?: UseQueryOptions<any[]>
) => {
  return useQuery({
    queryKey: [...queryKeys.recentActivity, limit],
    queryFn: () => apiService.getRecentActivity(limit),
    staleTime: 1 * 60 * 1000, // 1 minute
    refetchInterval: 30000, // Refetch every 30 seconds
    ...options,
  });
};

// ===================
// NOTIFICATION HOOKS
// ===================

// Get notifications
export const useNotifications = (
  params?: QueryParams,
  options?: UseQueryOptions<PaginatedResponse<Notification>>
) => {
  return useQuery({
    queryKey: [...queryKeys.notifications, params],
    queryFn: () => apiService.getNotifications(params),
    staleTime: 1 * 60 * 1000, // 1 minute
    refetchInterval: 30000, // Refetch every 30 seconds
    ...options,
  });
};

// Mark notification as read mutation
export const useMarkNotificationAsRead = (
  options?: UseMutationOptions<Notification, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.markNotificationAsRead(id),
    onSuccess: () => {
      // Invalidate notifications
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications });
    },
    ...options,
  });
};

// Mark all notifications as read mutation
export const useMarkAllNotificationsAsRead = (
  options?: UseMutationOptions<void, Error, void>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: () => apiService.markAllNotificationsAsRead(),
    onSuccess: () => {
      // Invalidate notifications
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications });
    },
    ...options,
  });
};

// Delete notification mutation
export const useDeleteNotification = (
  options?: UseMutationOptions<void, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: number) => apiService.deleteNotification(id),
    onSuccess: () => {
      // Invalidate notifications
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications });
    },
    ...options,
  });
};

// ===================
// SEARCH HOOKS
// ===================

// Global search
export const useSearch = (
  request: SearchRequest,
  options?: UseQueryOptions<SearchResponse>
) => {
  return useQuery({
    queryKey: [...queryKeys.search(request.query), request],
    queryFn: () => apiService.search(request),
    enabled: !!request.query && request.query.length > 0,
    staleTime: 5 * 60 * 1000,
    ...options,
  });
};

// Search suggestions
export const useSearchSuggestions = (
  query: string,
  options?: UseQueryOptions<string[]>
) => {
  return useQuery({
    queryKey: queryKeys.searchSuggestions(query),
    queryFn: () => apiService.getSearchSuggestions(query),
    enabled: !!query && query.length > 2,
    staleTime: 10 * 60 * 1000,
    ...options,
  });
};

// ===================
// EXPORT/IMPORT HOOKS
// ===================

// Export data mutation
export const useExportData = (
  options?: UseMutationOptions<Blob, Error, ExportRequest>
) => {
  return useMutation({
    mutationFn: (request: ExportRequest) => apiService.exportData(request),
    ...options,
  });
};

// Import data mutation
export const useImportData = (
  options?: UseMutationOptions<ImportResult, Error, ImportRequest>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (request: ImportRequest) => apiService.importData(request),
    onSuccess: () => {
      // Invalidate relevant queries based on import type
      queryClient.invalidateQueries({ queryKey: queryKeys.targets });
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
      queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
    },
    ...options,
  });
};

// ===================
// SYSTEM HOOKS
// ===================

// Get system information
export const useSystemInfo = (
  options?: UseQueryOptions<any>
) => {
  return useQuery({
    queryKey: queryKeys.systemInfo,
    queryFn: () => apiService.getSystemInfo(),
    staleTime: 10 * 60 * 1000, // 10 minutes
    ...options,
  });
};

// Health check
export const useHealthCheck = (
  options?: UseQueryOptions<{ status: string; timestamp: string }>
) => {
  return useQuery({
    queryKey: queryKeys.healthCheck,
    queryFn: () => apiService.healthCheck(),
    staleTime: 1 * 60 * 1000, // 1 minute
    refetchInterval: 60000, // Check every minute
    ...options,
  });
};

// ===================
// FILE UPLOAD HOOKS
// ===================

// Upload file mutation
export const useUploadFile = (
  options?: UseMutationOptions<
    { url: string; filename: string },
    Error,
    { file: File; onProgress?: (progress: number) => void }
  >
) => {
  return useMutation({
    mutationFn: ({ file, onProgress }) => apiService.uploadFile(file, onProgress),
    ...options,
  });
};

// Delete file mutation
export const useDeleteFile = (
  options?: UseMutationOptions<void, Error, string>
) => {
  return useMutation({
    mutationFn: (filename: string) => apiService.deleteFile(filename),
    ...options,
  });
};

// ===================
// UTILITY HOOKS
// ===================

// Invalidate all queries
export const useInvalidateAllQueries = () => {
  const queryClient = useQueryClient();
  
  return useCallback(() => {
    queryClient.invalidateQueries();
  }, [queryClient]);
};

// Prefetch target
export const usePrefetchTarget = () => {
  const queryClient = useQueryClient();
  
  return useCallback((id: number) => {
    queryClient.prefetchQuery({
      queryKey: queryKeys.target(id),
      queryFn: () => apiService.getTarget(id),
      staleTime: 5 * 60 * 1000,
    });
  }, [queryClient]);
};

// Prefetch scan
export const usePrefetchScan = () => {
  const queryClient = useQueryClient();
  
  return useCallback((id: number) => {
    queryClient.prefetchQuery({
      queryKey: queryKeys.scan(id),
      queryFn: () => apiService.getScan(id),
      staleTime: 1 * 60 * 1000,
    });
  }, [queryClient]);
};

// Check if API is available
export const useApiAvailability = () => {
  return useQuery({
    queryKey: ['api', 'availability'],
    queryFn: () => apiService.isApiAvailable(),
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 30 * 1000, // Check every 30 seconds
    retry: false,
  });
};