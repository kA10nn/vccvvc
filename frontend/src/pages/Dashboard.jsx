import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  LinearProgress,
  Chip,
  IconButton,
  Tooltip,
  Alert,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { fetchAgents } from '../store/agentSlice';
import AgentService from '../services/agentService';
import { formatDistanceToNow } from 'date-fns';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

const Dashboard = () => {
  const dispatch = useDispatch();
  const { agents, isLoading } = useSelector((state) => state.agents);
  const [stats, setStats] = useState({
    totalTasks: 0,
    pendingTasks: 0,
    failedTasks: 0,
    recentActivity: [],
  });
  const [systemInfo, setSystemInfo] = useState({
    uptime: 0,
    memory: { used: 0, total: 0 },
    cpu: 0,
  });

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    dispatch(fetchAgents());
    
    try {
      const [tasks, activity, system] = await Promise.all([
        AgentService.getTasks(),
        AgentService.getActivity(),
        AgentService.getSystemInfo(),
      ]);
      
      const pendingTasks = tasks.filter(t => t.status === 'pending').length;
      const failedTasks = tasks.filter(t => t.status === 'failed').length;
      
      setStats({
        totalTasks: tasks.length,
        pendingTasks,
        failedTasks,
        recentActivity: activity.slice(0, 5),
      });
      
      if (system) {
        setSystemInfo(system);
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  const onlineAgents = agents.filter(a => a.status === 'online').length;
  const offlineAgents = agents.filter(a => a.status === 'offline').length;

  const agentOsData = agents.reduce((acc, agent) => {
    const os = agent.os || 'Unknown';
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const pieData = Object.entries(agentOsData).map(([name, value]) => ({
    name,
    value,
  }));

  const lineData = agents.map(agent => ({
    name: agent.hostname.substring(0, 10),
    lastSeen: agent.last_seen ? 
      formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true }) : 'Never',
    status: agent.status === 'online' ? 1 : 0,
  }));

  const StatCard = ({ title, value, icon, color, subtitle, trend }) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box>
            <Typography color="textSecondary" gutterBottom variant="overline">
              {title}
            </Typography>
            <Typography variant="h4" component="div">
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="caption" color="textSecondary">
                {subtitle}
              </Typography>
            )}
            {trend && (
              <Typography variant="caption" color={trend > 0 ? 'success.main' : 'error.main'}>
                {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
              </Typography>
            )}
          </Box>
          <Box sx={{ color: `${color}.main` }}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  const SystemHealthCard = () => (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          System Health
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box display="flex" justifyContent="space-between" mb={0.5}>
            <Typography variant="body2">CPU Usage</Typography>
            <Typography variant="body2">{systemInfo.cpu}%</Typography>
          </Box>
          <LinearProgress 
            variant="determinate" 
            value={systemInfo.cpu} 
            color={systemInfo.cpu > 80 ? 'error' : systemInfo.cpu > 60 ? 'warning' : 'primary'}
          />
        </Box>
        <Box>
          <Box display="flex" justifyContent="space-between" mb={0.5}>
            <Typography variant="body2">Memory Usage</Typography>
            <Typography variant="body2">
              {Math.round(systemInfo.memory.used / 1024 / 1024)}MB / 
              {Math.round(systemInfo.memory.total / 1024 / 1024)}MB
            </Typography>
          </Box>
          <LinearProgress 
            variant="determinate" 
            value={(systemInfo.memory.used / systemInfo.memory.total) * 100} 
            color={(systemInfo.memory.used / systemInfo.memory.total) * 100 > 80 ? 'error' : 'primary'}
          />
        </Box>
        <Typography variant="caption" color="textSecondary" sx={{ mt: 2, display: 'block' }}>
          Uptime: {Math.floor(systemInfo.uptime / 3600)}h {Math.floor((systemInfo.uptime % 3600) / 60)}m
        </Typography>
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" fontWeight="bold">
          Dashboard
        </Typography>
        <Tooltip title="Refresh">
          <IconButton onClick={loadDashboardData} disabled={isLoading}>
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Box>

      {agents.length === 0 && !isLoading && (
        <Alert severity="info" sx={{ mb: 3 }}>
          No agents connected. Start the implant on target systems to see them here.
        </Alert>
      )}

      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Agents"
            value={agents.length}
            icon={<ComputerIcon sx={{ fontSize: 40 }} />}
            color="primary"
            subtitle={`${onlineAgents} online`}
          />
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Online Agents"
            value={onlineAgents}
            icon={<CheckCircleIcon sx={{ fontSize: 40 }} />}
            color="success"
            subtitle={`${offlineAgents} offline`}
          />
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Pending Tasks"
            value={stats.pendingTasks}
            icon={<StorageIcon sx={{ fontSize: 40 }} />}
            color="warning"
            subtitle={`${stats.totalTasks} total`}
          />
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="System Status"
            value="Operational"
            icon={<SecurityIcon sx={{ fontSize: 40 }} />}
            color="info"
            subtitle="All systems normal"
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Agent Activity Timeline
            </Typography>
            <ResponsiveContainer width="100%" height="80%">
              <LineChart data={lineData.slice(0, 10)}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis domain={[0, 1]} ticks={[0, 1]} />
                <ChartTooltip />
                <Line 
                  type="monotone" 
                  dataKey="status" 
                  stroke="#8884d8" 
                  strokeWidth={2}
                  dot={{ r: 4 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <SystemHealthCard />
        </Grid>
      </Grid>

      <Grid container spacing={3} sx={{ mt: 1 }}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: 300 }}>
            <Typography variant="h6" gutterBottom>
              Agent OS Distribution
            </Typography>
            <ResponsiveContainer width="100%" height="80%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <ChartTooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: 300, overflow: 'auto' }}>
            <Typography variant="h6" gutterBottom>
              Recent Activity
            </Typography>
            <Box>
              {stats.recentActivity.map((activity, index) => (
                <Box
                  key={index}
                  sx={{
                    p: 2,
                    mb: 1,
                    borderRadius: 1,
                    bgcolor: 'background.default',
                    border: '1px solid',
                    borderColor: 'divider',
                  }}
                >
                  <Box display="flex" alignItems="center">
                    {activity.type === 'error' ? (
                      <ErrorIcon color="error" sx={{ mr: 1, fontSize: 16 }} />
                    ) : activity.type === 'warning' ? (
                      <WarningIcon color="warning" sx={{ mr: 1, fontSize: 16 }} />
                    ) : (
                      <CheckCircleIcon color="success" sx={{ mr: 1, fontSize: 16 }} />
                    )}
                    <Box flexGrow={1}>
                      <Typography variant="body2">
                        {activity.message}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {activity.timestamp && formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                      </Typography>
                    </Box>
                    {activity.agent && (
                      <Chip
                        label={activity.agent.substring(0, 8)}
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>
                </Box>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
