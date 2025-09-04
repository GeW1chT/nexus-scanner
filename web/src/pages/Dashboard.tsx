import React from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  LinearProgress,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Assessment as ReportIcon,
  Notifications as NotificationsIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  PlayArrow as PlayArrowIcon,
} from '@mui/icons-material';
import { useDashboardStats, useScans, useVulnerabilities } from '../hooks/useApi';
import LoadingSpinner from '../components/UI/LoadingSpinner';
import { getRelativeTime } from '../utils';

const Dashboard: React.FC = () => {
  const { data: stats, isLoading: statsLoading } = useDashboardStats();
  const { data: recentScansData, isLoading: scansLoading } = useScans({ limit: 5 });
  const { data: recentVulnData, isLoading: vulnLoading } = useVulnerabilities({ limit: 5 });

  const recentScans = recentScansData?.data || [];
  const recentVulnerabilities = recentVulnData?.data || [];

  if (statsLoading) {
    return <LoadingSpinner message="Dashboard yükleniyor..." />;
  }

  const statCards = [
    {
      title: 'Toplam Hedef',
      value: stats?.totalTargets || 0,
      icon: <SecurityIcon />,
      color: 'primary.main',
      trend: '+12%',
    },
    {
      title: 'Aktif Tarama',
      value: stats?.activeScans || 0,
      icon: <PlayArrowIcon />,
      color: 'success.main',
      trend: '+5%',
    },
    {
      title: 'Güvenlik Açığı',
      value: stats?.totalVulnerabilities || 0,
      icon: <BugReportIcon />,
      color: 'error.main',
      trend: '-8%',
    },
    {
      title: 'Oluşturulan Rapor',
      value: stats?.totalReports || 0,
      icon: <ReportIcon />,
      color: 'info.main',
      trend: '+15%',
    },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <ErrorIcon />;
      case 'high':
        return <WarningIcon />;
      case 'medium':
        return <NotificationsIcon />;
      case 'low':
        return <CheckCircleIcon />;
      default:
        return <BugReportIcon />;
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Güvenlik tarama sistemine genel bakış
      </Typography>

      {/* İstatistik Kartları */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {statCards.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      {stat.title}
                    </Typography>
                    <Typography variant="h4">
                      {stat.value.toLocaleString()}
                    </Typography>
                    <Box display="flex" alignItems="center" mt={1}>
                      <TrendingUpIcon fontSize="small" color="success" />
                      <Typography variant="body2" color="success.main" ml={0.5}>
                        {stat.trend}
                      </Typography>
                    </Box>
                  </Box>
                  <Box
                    sx={{
                      p: 1,
                      borderRadius: 1,
                      bgcolor: `${stat.color}15`,
                      color: stat.color,
                    }}
                  >
                    {stat.icon}
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={3}>
        {/* Son Taramalar */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Son Taramalar
            </Typography>
            {scansLoading ? (
              <LoadingSpinner message="Taramalar yükleniyor..." />
            ) : (
              <List>
                {recentScans.slice(0, 5).map((scan: any) => (
                  <ListItem key={scan.id} divider>
                    <ListItemIcon>
                      <PlayArrowIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={scan.target?.url || scan.target?.name}
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            {getRelativeTime(scan.createdAt)}
                          </Typography>
                          <Box mt={0.5}>
                            <Chip
                              size="small"
                              label={scan.status}
                              color={
                                scan.status === 'completed'
                                  ? 'success'
                                  : scan.status === 'running'
                                  ? 'primary'
                                  : 'default'
                              }
                            />
                          </Box>
                          {scan.status === 'running' && scan.progress && (
                            <Box mt={1}>
                              <LinearProgress
                                variant="determinate"
                                value={scan.progress}
                                sx={{ height: 4, borderRadius: 2 }}
                              />
                            </Box>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paper>
        </Grid>

        {/* Son Güvenlik Açıkları */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Son Güvenlik Açıkları
            </Typography>
            {vulnLoading ? (
              <LoadingSpinner message="Güvenlik açıkları yükleniyor..." />
            ) : (
              <List>
                {recentVulnerabilities.slice(0, 5).map((vuln: any) => (
                  <ListItem key={vuln.id} divider>
                    <ListItemIcon>
                      {getSeverityIcon(vuln.severity)}
                    </ListItemIcon>
                    <ListItemText
                      primary={vuln.title}
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            {vuln.target?.url || vuln.target?.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {getRelativeTime(vuln.createdAt)}
                          </Typography>
                          <Box mt={0.5}>
                            <Chip
                              size="small"
                              label={vuln.severity}
                              color={getSeverityColor(vuln.severity) as any}
                            />
                          </Box>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;