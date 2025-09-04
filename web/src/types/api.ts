// Base API Response Interface
export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message?: string;
  errors?: ApiError[];
  meta?: ResponseMeta;
}

// Paginated API Response Interface
export interface PaginatedResponse<T = any> {
  success: boolean;
  data: T[];
  pagination: PaginationMeta;
  message?: string;
  errors?: ApiError[];
}

// API Error Interface
export interface ApiError {
  code: string;
  message: string;
  field?: string;
  details?: Record<string, any>;
}

// Response Meta Interface
export interface ResponseMeta {
  timestamp: string;
  requestId: string;
  version: string;
  executionTime?: number;
}

// Pagination Meta Interface
export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

// Query Parameters Interface
export interface QueryParams {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  search?: string;
  filter?: Record<string, any>;
  include?: string[];
  fields?: string[];
}

// Target Interfaces
export interface Target {
  id: number;
  url: string;
  name: string;
  description?: string;
  type: TargetType;
  status: TargetStatus;
  tags: string[];
  metadata: TargetMetadata;
  createdAt: string;
  updatedAt: string;
  lastScanAt?: string;
  userId: number;
}

export enum TargetType {
  WEB = 'web',
  API = 'api',
  NETWORK = 'network',
  MOBILE = 'mobile',
}

export enum TargetStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  ARCHIVED = 'archived',
  PENDING = 'pending',
}

export interface TargetMetadata {
  domain?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  technology?: string[];
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  authentication?: AuthenticationConfig;
}

export interface AuthenticationConfig {
  type: 'none' | 'basic' | 'bearer' | 'oauth' | 'custom';
  credentials?: Record<string, string>;
  headers?: Record<string, string>;
}

// Scan Interfaces
export interface Scan {
  id: number;
  targetId: number;
  target: Target;
  name: string;
  description?: string;
  type: ScanType;
  status: ScanStatus;
  progress: number;
  config: ScanConfig;
  results: ScanResults;
  startedAt?: string;
  completedAt?: string;
  duration?: number;
  createdAt: string;
  updatedAt: string;
  userId: number;
}

export enum ScanType {
  VULNERABILITY = 'vulnerability',
  SECURITY = 'security',
  PERFORMANCE = 'performance',
  COMPLIANCE = 'compliance',
  CUSTOM = 'custom',
}

export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  PAUSED = 'paused',
}

export interface ScanConfig {
  modules: string[];
  depth: number;
  timeout: number;
  concurrent: number;
  userAgent?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  authentication?: AuthenticationConfig;
  excludePatterns?: string[];
  includePatterns?: string[];
  customRules?: CustomRule[];
}

export interface CustomRule {
  id: string;
  name: string;
  description: string;
  pattern: string;
  severity: VulnerabilitySeverity;
  category: string;
}

export interface ScanResults {
  summary: ScanSummary;
  vulnerabilities: Vulnerability[];
  findings: Finding[];
  statistics: ScanStatistics;
  logs: ScanLog[];
}

export interface ScanSummary {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  pagesScanned: number;
  requestsSent: number;
  errorsEncountered: number;
}

export interface ScanStatistics {
  startTime: string;
  endTime: string;
  duration: number;
  averageResponseTime: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  bytesTransferred: number;
}

export interface ScanLog {
  id: string;
  timestamp: string;
  level: LogLevel;
  message: string;
  module: string;
  details?: Record<string, any>;
}

export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  CRITICAL = 'critical',
}

// Vulnerability Interfaces
export interface Vulnerability {
  id: number;
  scanId: number;
  name: string;
  description: string;
  severity: VulnerabilitySeverity;
  category: VulnerabilityCategory;
  cwe?: string;
  cvss?: CVSSScore;
  url: string;
  method: string;
  parameter?: string;
  payload?: string;
  evidence: Evidence;
  impact: string;
  recommendation: string;
  references: Reference[];
  status: VulnerabilityStatus;
  falsePositive: boolean;
  verified: boolean;
  createdAt: string;
  updatedAt: string;
}

export enum VulnerabilitySeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum VulnerabilityCategory {
  INJECTION = 'injection',
  XSS = 'xss',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  CRYPTOGRAPHY = 'cryptography',
  CONFIGURATION = 'configuration',
  INFORMATION_DISCLOSURE = 'information_disclosure',
  INPUT_VALIDATION = 'input_validation',
  SESSION_MANAGEMENT = 'session_management',
  OTHER = 'other',
}

export enum VulnerabilityStatus {
  OPEN = 'open',
  FIXED = 'fixed',
  ACCEPTED = 'accepted',
  FALSE_POSITIVE = 'false_positive',
  DUPLICATE = 'duplicate',
}

export interface CVSSScore {
  version: string;
  vector: string;
  baseScore: number;
  temporalScore?: number;
  environmentalScore?: number;
  severity: string;
}

export interface Evidence {
  request?: string;
  response?: string;
  screenshot?: string;
  proof?: string;
  location?: string;
  context?: string;
}

export interface Reference {
  title: string;
  url: string;
  type: 'cve' | 'cwe' | 'owasp' | 'advisory' | 'blog' | 'documentation' | 'other';
}

// Finding Interface (for non-vulnerability findings)
export interface Finding {
  id: number;
  scanId: number;
  type: FindingType;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  url: string;
  evidence: Evidence;
  recommendation?: string;
  createdAt: string;
}

export enum FindingType {
  INFORMATION = 'information',
  CONFIGURATION = 'configuration',
  BEST_PRACTICE = 'best_practice',
  PERFORMANCE = 'performance',
  ACCESSIBILITY = 'accessibility',
  SEO = 'seo',
}

// Report Interfaces
export interface Report {
  id: number;
  scanId: number;
  scan: Scan;
  name: string;
  description?: string;
  format: ReportFormat;
  template: string;
  config: ReportConfig;
  status: ReportStatus;
  filePath?: string;
  fileSize?: number;
  downloadUrl?: string;
  createdAt: string;
  updatedAt: string;
  userId: number;
}

export enum ReportFormat {
  HTML = 'html',
  PDF = 'pdf',
  JSON = 'json',
  XML = 'xml',
  CSV = 'csv',
  DOCX = 'docx',
}

export enum ReportStatus {
  PENDING = 'pending',
  GENERATING = 'generating',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export interface ReportConfig {
  includeExecutiveSummary: boolean;
  includeVulnerabilities: boolean;
  includeFindings: boolean;
  includeLogs: boolean;
  includeScreenshots: boolean;
  includeRecommendations: boolean;
  severityFilter: VulnerabilitySeverity[];
  customSections?: ReportSection[];
  branding?: ReportBranding;
}

export interface ReportSection {
  id: string;
  title: string;
  content: string;
  order: number;
  enabled: boolean;
}

export interface ReportBranding {
  logo?: string;
  companyName?: string;
  colors?: {
    primary: string;
    secondary: string;
    accent: string;
  };
}

// Dashboard Interfaces
export interface DashboardStats {
  totalTargets: number;
  activeScans: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  totalReports: number;
  recentScans: Scan[];
  vulnerabilityTrends: VulnerabilityTrend[];
  scanActivity: ScanActivity[];
  topVulnerabilities: TopVulnerability[];
}

export interface VulnerabilityTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanActivity {
  date: string;
  scansCompleted: number;
  scansStarted: number;
  scansFailed: number;
}

export interface TopVulnerability {
  name: string;
  count: number;
  severity: VulnerabilitySeverity;
  category: VulnerabilityCategory;
}

// Notification Interfaces
export interface Notification {
  id: number;
  userId: number;
  type: NotificationType;
  title: string;
  message: string;
  data?: Record<string, any>;
  read: boolean;
  createdAt: string;
  readAt?: string;
}

export enum NotificationType {
  SCAN_COMPLETED = 'scan_completed',
  SCAN_FAILED = 'scan_failed',
  VULNERABILITY_FOUND = 'vulnerability_found',
  REPORT_GENERATED = 'report_generated',
  SYSTEM_UPDATE = 'system_update',
  SECURITY_ALERT = 'security_alert',
}

// System Interfaces
export interface SystemInfo {
  version: string;
  buildDate: string;
  environment: string;
  uptime: number;
  memoryUsage: MemoryUsage;
  diskUsage: DiskUsage;
  databaseStatus: DatabaseStatus;
  serviceStatus: ServiceStatus[];
}

export interface MemoryUsage {
  total: number;
  used: number;
  free: number;
  percentage: number;
}

export interface DiskUsage {
  total: number;
  used: number;
  free: number;
  percentage: number;
}

export interface DatabaseStatus {
  connected: boolean;
  responseTime: number;
  activeConnections: number;
  maxConnections: number;
}

export interface ServiceStatus {
  name: string;
  status: 'running' | 'stopped' | 'error';
  uptime: number;
  lastCheck: string;
}

// WebSocket Interfaces
export enum WebSocketMessageType {
  HEARTBEAT = 'heartbeat',
  CONNECTION_ACK = 'connection_ack',
  ERROR = 'error',
  SCAN_UPDATE = 'scan_update',
  NOTIFICATION = 'notification',
  SYSTEM_STATUS = 'system_status',
  SUBSCRIBE = 'subscribe',
  UNSUBSCRIBE = 'unsubscribe',
}

export interface WebSocketMessage {
  type: WebSocketMessageType | string;
  data: any;
  timestamp: string;
  id?: string;
}

export interface ScanProgressMessage {
  scanId: number;
  progress: number;
  status: ScanStatus;
  currentModule?: string;
  message?: string;
}

export interface NotificationMessage {
  notification: Notification;
}

// File Upload Interfaces
export interface FileUpload {
  file: File;
  progress: number;
  status: 'pending' | 'uploading' | 'completed' | 'error';
  error?: string;
  url?: string;
}

// Export/Import Interfaces
export interface ExportRequest {
  type: 'targets' | 'scans' | 'vulnerabilities' | 'reports';
  format: 'json' | 'csv' | 'xml';
  filters?: Record<string, any>;
  includeRelated?: boolean;
}

export interface ImportRequest {
  type: 'targets' | 'scans' | 'vulnerabilities';
  format: 'json' | 'csv' | 'xml';
  file: File;
  options?: ImportOptions;
}

export interface ImportOptions {
  skipDuplicates?: boolean;
  updateExisting?: boolean;
  validateData?: boolean;
  dryRun?: boolean;
}

export interface ImportResult {
  success: boolean;
  imported: number;
  skipped: number;
  errors: number;
  warnings: string[];
  details?: Record<string, any>;
}

// Search Interfaces
export interface SearchRequest {
  query: string;
  type?: 'targets' | 'scans' | 'vulnerabilities' | 'all';
  filters?: SearchFilters;
  pagination?: QueryParams;
}

export interface SearchFilters {
  severity?: VulnerabilitySeverity[];
  category?: VulnerabilityCategory[];
  status?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  tags?: string[];
}

export interface SearchResult<T = any> {
  type: string;
  item: T;
  score: number;
  highlights?: Record<string, string[]>;
}

export interface SearchResponse<T = any> {
  results: SearchResult<T>[];
  total: number;
  took: number;
  suggestions?: string[];
}

// Utility Types
export type SortOrder = 'asc' | 'desc';
export type FilterOperator = 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'nin' | 'like' | 'regex';

export interface Filter {
  field: string;
  operator: FilterOperator;
  value: any;
}

export interface Sort {
  field: string;
  order: SortOrder;
}

// Constants
export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;
export const DEFAULT_TIMEOUT = 30000;
export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

export const SEVERITY_COLORS = {
  [VulnerabilitySeverity.CRITICAL]: '#d32f2f',
  [VulnerabilitySeverity.HIGH]: '#f57c00',
  [VulnerabilitySeverity.MEDIUM]: '#fbc02d',
  [VulnerabilitySeverity.LOW]: '#388e3c',
  [VulnerabilitySeverity.INFO]: '#1976d2',
};

export const STATUS_COLORS = {
  [ScanStatus.PENDING]: '#9e9e9e',
  [ScanStatus.RUNNING]: '#2196f3',
  [ScanStatus.COMPLETED]: '#4caf50',
  [ScanStatus.FAILED]: '#f44336',
  [ScanStatus.CANCELLED]: '#ff9800',
  [ScanStatus.PAUSED]: '#9c27b0',
};

// Type Guards
export const isApiResponse = <T>(obj: any): obj is ApiResponse<T> => {
  return obj && typeof obj.success === 'boolean';
};

export const isPaginatedResponse = <T>(obj: any): obj is PaginatedResponse<T> => {
  return obj && 
    typeof obj.success === 'boolean' &&
    Array.isArray(obj.data) &&
    obj.pagination &&
    typeof obj.pagination.page === 'number';
};

export const isTarget = (obj: any): obj is Target => {
  return obj &&
    typeof obj.id === 'number' &&
    typeof obj.url === 'string' &&
    Object.values(TargetType).includes(obj.type);
};

export const isScan = (obj: any): obj is Scan => {
  return obj &&
    typeof obj.id === 'number' &&
    typeof obj.targetId === 'number' &&
    Object.values(ScanType).includes(obj.type) &&
    Object.values(ScanStatus).includes(obj.status);
};

export const isVulnerability = (obj: any): obj is Vulnerability => {
  return obj &&
    typeof obj.id === 'number' &&
    typeof obj.scanId === 'number' &&
    Object.values(VulnerabilitySeverity).includes(obj.severity);
};