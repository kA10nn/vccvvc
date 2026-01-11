import React, { useState, useEffect } from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Paper, Chip, IconButton, Tooltip, TextField, Box, Typography,
  Dialog, DialogTitle, DialogContent, DialogActions, Button,
  Menu, MenuItem, InputAdornment, Grid, Card, CardContent
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  MoreVert as MoreVertIcon,
  PlayArrow as ExecuteIcon,
  GetApp as DownloadIcon,
  Delete as DeleteIcon,
  Terminal as TerminalIcon,
  Search as SearchIcon,
  Computer as ComputerIcon,
  Schedule as ScheduleIcon
} from '@mui/icons-material';
import AgentService from '../services/agentService';
import TaskCreator from './TaskCreator';
import { useSnackbar } from 'notistack';

const AgentManager = () => {
  const [agents, setAgents] = useState([]);
  const [filteredAgents, setFilteredAgents] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [taskDialogOpen, setTaskDialogOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [loading, setLoading] = useState(false);
  const { enqueueSnackbar } = useSnackbar();

  useEffect(() => {
    loadAgents();
    const interval = setInterval(loadAgents, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const filtered = agents.filter(agent =>
      agent.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.uuid.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.username.toLowerCase().includes(searchTerm.toLowerCase())
    );
    setFilteredAgents(filtered);
  }, [agents, searchTerm]);

  const loadAgents = async () => {
    try {
      const data = await AgentService.getAgents();
      setAgents(data);
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to load agents'), { variant: 'error' });
    }
  };

  const handleMenuClick = (event, agent) => {
    setAnchorEl(event.currentTarget);
    setSelectedAgent(agent);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleExecuteTask = () => {
    setTaskDialogOpen(true);
    handleMenuClose();
  };

  const handleDeleteAgent = async () => {
    if (!selectedAgent) return;
    
    if (window.confirm(`Delete agent ${selectedAgent.hostname}?`)) {
      try {
        await AgentService.deleteAgent(selectedAgent.uuid);
        enqueueSnackbar('Agent deleted', { variant: 'success' });
        loadAgents();
      } catch (error) {
        enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to delete agent'), { variant: 'error' });
      }
    }
    handleMenuClose();
  };

  const handleInteractiveShell = () => {
    // Open terminal interface
    window.open(`/terminal/${selectedAgent.uuid}`, '_blank');
    handleMenuClose();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'online': return 'success';
      case 'offline': return 'error';
      case 'sleeping': return 'warning';
      default: return 'default';
    }
  };

  const formatLastSeen = (timestamp) => {
    const diff = Date.now() - new Date(timestamp).getTime();
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    return `${Math.floor(minutes / 1440)}d ago`;
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Agent Management</Typography>
        <Box display="flex" alignItems="center" gap={2}>
          <TextField
            placeholder="Search agents..."
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
          <Tooltip title="Refresh">
            <IconButton onClick={loadAgents} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <ComputerIcon color="primary" sx={{ mr: 2, fontSize: 40 }} />
                <Box>
                  <Typography color="textSecondary">Total Agents</Typography>
                  <Typography variant="h4">{agents.length}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Chip label="Online" color="success" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="textSecondary">Active</Typography>
                  <Typography variant="h4">
                    {agents.filter(a => a.status === 'online').length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Status</TableCell>
              <TableCell>Hostname</TableCell>
              <TableCell>Username</TableCell>
              <TableCell>OS/Arch</TableCell>
              <TableCell>IP Address</TableCell>
              <TableCell>Last Seen</TableCell>
              <TableCell>Sleep</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredAgents.map((agent) => (
              <TableRow key={agent.uuid} hover>
                <TableCell>
                  <Chip
                    label={agent.status}
                    color={getStatusColor(agent.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box display="flex" alignItems="center">
                    <ComputerIcon sx={{ mr: 1, color: 'primary.main' }} />
                    <Typography fontWeight="medium">
                      {agent.hostname}
                    </Typography>
                  </Box>
                  <Typography variant="caption" color="textSecondary">
                    {agent.uuid.substring(0, 8)}...
                  </Typography>
                </TableCell>
                <TableCell>{agent.username}</TableCell>
                <TableCell>
                  <Chip
                    label={`${agent.os} ${agent.arch}`}
                    variant="outlined"
                    size="small"
                  />
                </TableCell>
                <TableCell>{agent.ip}</TableCell>
                <TableCell>
                  <Box display="flex" alignItems="center">
                    <ScheduleIcon sx={{ mr: 1, fontSize: 16 }} />
                    {formatLastSeen(agent.last_seen)}
                  </Box>
                </TableCell>
                <TableCell>{agent.sleep}s</TableCell>
                <TableCell align="right">
                  <Tooltip title="Execute Command">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSelectedAgent(agent);
                        setTaskDialogOpen(true);
                      }}
                    >
                      <ExecuteIcon />
                    </IconButton>
                  </Tooltip>
                  
                  <Tooltip title="Interactive Shell">
                    <IconButton
                      size="small"
                      onClick={() => handleInteractiveShell(agent)}
                    >
                      <TerminalIcon />
                    </IconButton>
                  </Tooltip>
                  
                  <IconButton
                    size="small"
                    onClick={(e) => handleMenuClick(e, agent)}
                  >
                    <MoreVertIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleExecuteTask}>
          <ExecuteIcon sx={{ mr: 1 }} /> Execute Task
        </MenuItem>
        <MenuItem onClick={handleInteractiveShell}>
          <TerminalIcon sx={{ mr: 1 }} /> Interactive Shell
        </MenuItem>
        <MenuItem>
          <DownloadIcon sx={{ mr: 1 }} /> Download Files
        </MenuItem>
        <MenuItem onClick={handleDeleteAgent} sx={{ color: 'error.main' }}>
          <DeleteIcon sx={{ mr: 1 }} /> Delete Agent
        </MenuItem>
      </Menu>

      <Dialog
        open={taskDialogOpen}
        onClose={() => setTaskDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Execute Task on {selectedAgent?.hostname}
        </DialogTitle>
        <DialogContent>
          <TaskCreator
            agentId={selectedAgent?.uuid}
            onSuccess={() => {
              setTaskDialogOpen(false);
              enqueueSnackbar('Task created successfully', { variant: 'success' });
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTaskDialogOpen(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AgentManager;
