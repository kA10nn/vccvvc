import React, { useEffect, useState } from 'react';
import {
  Grid, Paper, Typography, Box, Card, CardContent,
  LinearProgress, Chip, IconButton, Tooltip, Badge
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as ChartTooltip, ResponsiveContainer } from 'recharts';
import { useWebSocket } from '../hooks/useWebSocket';
import AgentService from '../services/agentService';
import { enqueueSnackbar } from 'notistack';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalAgents: 0,
    onlineAgents: 0,
    pendingTasks: 0,
    totalTasks: 0,
    recentActivity: []
  });
  
  const [chartData, setChartData] = useState([]);
  const { messages } = useWebSocket();

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (messages.length > 0) {
      const lastMessage = messages[messages.length - 1];
      if (lastMessage.type === 'agent_connected' || lastMessage.type === 'task_completed') {
        loadDashboardData();
      }
    }
  }, [messages]);

  const loadDashboardData = async () => {
    try {
      const [agents, tasks, activity] = await Promise.all([
        AgentService.getAgents(),
        AgentService.getTasks(),
        AgentService.getActivity()
      ]);
      
      const onlineAgents = agents.filter(a => a.status === 'online').length;
      
      setStats({
        totalAgents: agents.length,
        onlineAgents,
        pendingTasks: tasks.filter(t => t.status === 'pending').length,
        totalTasks: tasks.length,
        recentActivity: activity.slice(0, 10)
      });
      
      // Update chart data
      const newDataPoint = {
        time: new Date().toLocaleTimeString(),
        agents: onlineAgents,
        tasks: tasks.length
      };
      
      setChartData(prev => {
        const updated = [...prev, newDataPoint];
        return updated.length > 20 ? updated.slice(1) : updated;
      });
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to load dashboard data'), { variant: 'error' });
    }
  };

  const StatCard = ({ title, value, icon, color, subtitle }) => (
    <Card sx={{ height: '100%', bgcolor: `${color}.50` }}>
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
          </Box>
          <Box sx={{ color: `${color}.main` }}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" fontWeight="bold">
          ARES Command Center
        </Typography>
        <Tooltip title="Refresh">
          <IconButton onClick={loadDashboardData}>
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Box>

      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Agents"
            value={stats.totalAgents}
            icon={<ComputerIcon sx={{ fontSize: 40 }} />}
            color="primary"
            subtitle={`${stats.onlineAgents} online`}
          />
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Online Agents"
            value={stats.onlineAgents}
            icon={<CheckCircleIcon sx={{ fontSize: 40 }} />}
            color="success"
            subtitle={`${stats.totalAgents - stats.onlineAgents} offline`}
          />
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Pending Tasks"
            value={stats.pendingTasks}
            icon={<StorageIcon sx={{ fontSize: 40 }} />}
            color="warning"
            subtitle={`${stats.totalTasks} total tasks`}
          />
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Security Status"
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
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <ChartTooltip />
                <Line type="monotone" dataKey="agents" stroke="#8884d8" strokeWidth={2} />
                <Line type="monotone" dataKey="tasks" stroke="#82ca9d" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, height: 400, overflow: 'auto' }}>
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
                    bgcolor: activity.type === 'alert' ? 'error.light' : 'background.default'
                  }}
                >
                  <Box display="flex" alignItems="center">
                    {activity.type === 'alert' ? (
                      <WarningIcon color="error" sx={{ mr: 1 }} />
                    ) : (
                      <CheckCircleIcon color="success" sx={{ mr: 1 }} />
                    )}
                    <Box flexGrow={1}>
                      <Typography variant="body2">
                        {activity.message}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {new Date(activity.time).toLocaleString()}
                      </Typography>
                    </Box>
                    <Chip
                      label={activity.agent_id?.substring(0, 8) || 'System'}
                      size="small"
                      variant="outlined"
                    />
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
