import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  IconButton,
  Tooltip,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormGroup,
  FormControlLabel as MUIFormControlLabel,
} from '@mui/material';
import {
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  VisibilityOff as ViewOffIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  Storage as StorageIcon,
  Code as CodeIcon,
  VpnKey as KeyIcon,
  Webhook as WebhookIcon,
  Edit as EditIcon,
  Visibility as VisibilityIcon,
} from '@mui/icons-material';
import { useFormik } from 'formik';
import * as yup from 'yup';
import SettingsService from '../services/settingsService';
import { enqueueSnackbar } from 'notistack';

const Settings = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [settings, setSettings] = useState({});
  const [apiKeys, setApiKeys] = useState([]);
  const [webhooks, setWebhooks] = useState([]);
  const [showApiKey, setShowApiKey] = useState({});

  useEffect(() => {
    loadSettings();
    loadApiKeys();
    loadWebhooks();
  }, []);

  const loadSettings = async () => {
    setIsLoading(true);
    try {
      const data = await SettingsService.getSettings();
      setSettings(data);
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to load settings'), { variant: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const loadApiKeys = async () => {
    try {
      const data = await SettingsService.getApiKeys();
      setApiKeys(data);
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to load API keys'), { variant: 'error' });
    }
  };

  const loadWebhooks = async () => {
    try {
      const data = await SettingsService.getWebhooks();
      setWebhooks(data);
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to load webhooks'), { variant: 'error' });
    }
  };

  const handleSaveSettings = async (values) => {
    setIsLoading(true);
    try {
      await SettingsService.updateSettings(values);
      enqueueSnackbar('Settings saved successfully', { variant: 'success' });
      loadSettings();
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to save settings'), { variant: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateApiKey = async () => {
    const name = prompt('Enter API key name:');
    if (!name) return;

    try {
      const newKey = await SettingsService.createApiKey({ name });
      setApiKeys([...apiKeys, newKey]);
      setShowApiKey({ ...showApiKey, [newKey.id]: true });
      enqueueSnackbar('API key created successfully', { variant: 'success' });
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to create API key'), { variant: 'error' });
    }
  };

  const handleDeleteApiKey = async (id) => {
    if (!window.confirm('Are you sure you want to delete this API key?')) return;

    try {
      await SettingsService.deleteApiKey(id);
      setApiKeys(apiKeys.filter(key => key.id !== id));
      enqueueSnackbar('API key deleted', { variant: 'success' });
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to delete API key'), { variant: 'error' });
    }
  };

  const GeneralSettings = () => {
    const formik = useFormik({
      initialValues: {
        systemName: settings.system_name || 'ARES C2',
        systemVersion: settings.system_version || '1.0.0',
        sessionTimeout: settings.session_timeout || 3600,
        maxLoginAttempts: settings.max_login_attempts || 5,
        enableRegistration: settings.enable_registration || false,
        maintenanceMode: settings.maintenance_mode || false,
      },
      validationSchema: yup.object({
        systemName: yup.string().required('System name is required'),
        sessionTimeout: yup.number().min(60).max(86400),
        maxLoginAttempts: yup.number().min(1).max(10),
      }),
      onSubmit: handleSaveSettings,
      enableReinitialize: true,
    });

    return (
      <Box component="form" onSubmit={formik.handleSubmit}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              name="systemName"
              label="System Name"
              value={formik.values.systemName}
              onChange={formik.handleChange}
              error={formik.touched.systemName && Boolean(formik.errors.systemName)}
              helperText={formik.touched.systemName && formik.errors.systemName}
              size="small"
            />
          </Grid>
          
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              name="systemVersion"
              label="System Version"
              value={formik.values.systemVersion}
              onChange={formik.handleChange}
              size="small"
              disabled
            />
          </Grid>
          
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              name="sessionTimeout"
              label="Session Timeout (seconds)"
              type="number"
              value={formik.values.sessionTimeout}
              onChange={formik.handleChange}
              size="small"
              InputProps={{
                inputProps: { min: 60, max: 86400 },
              }}
            />
          </Grid>
          
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              name="maxLoginAttempts"
              label="Max Login Attempts"
              type="number"
              value={formik.values.maxLoginAttempts}
              onChange={formik.handleChange}
              size="small"
              InputProps={{
                inputProps: { min: 1, max: 10 },
              }}
            />
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="enableRegistration"
                  checked={formik.values.enableRegistration}
                  onChange={formik.handleChange}
                />
              }
              label="Enable User Registration"
            />
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="maintenanceMode"
                  checked={formik.values.maintenanceMode}
                  onChange={formik.handleChange}
                />
              }
              label="Maintenance Mode"
            />
          </Grid>
          
          <Grid item xs={12}>
            <Button
              type="submit"
              variant="contained"
              startIcon={<SaveIcon />}
              disabled={isLoading}
            >
              Save General Settings
            </Button>
          </Grid>
        </Grid>
      </Box>
    );
  };

  const SecuritySettings = () => {
    const formik = useFormik({
      initialValues: {
        require2FA: settings.require_2fa || false,
        enableIPWhitelist: settings.enable_ip_whitelist || false,
        ipWhitelist: settings.ip_whitelist || '',
        passwordMinLength: settings.password_min_length || 8,
        passwordRequireSpecial: settings.password_require_special || true,
        enableAuditLog: settings.enable_audit_log || true,
      },
      onSubmit: handleSaveSettings,
      enableReinitialize: true,
    });

    return (
      <Box component="form" onSubmit={formik.handleSubmit}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="info" sx={{ mb: 2 }}>
              Security settings control authentication and access controls
            </Alert>
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="require2FA"
                  checked={formik.values.require2FA}
                  onChange={formik.handleChange}
                />
              }
              label="Require Two-Factor Authentication"
            />
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="enableIPWhitelist"
                  checked={formik.values.enableIPWhitelist}
                  onChange={formik.handleChange}
                />
              }
              label="Enable IP Address Whitelist"
            />
          </Grid>
          
          {formik.values.enableIPWhitelist && (
            <Grid item xs={12}>
              <TextField
                fullWidth
                name="ipWhitelist"
                label="IP Whitelist (comma-separated)"
                value={formik.values.ipWhitelist}
                onChange={formik.handleChange}
                multiline
                rows={3}
                placeholder="192.168.1.1, 10.0.0.0/24"
                size="small"
              />
            </Grid>
          )}
          
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              name="passwordMinLength"
              label="Minimum Password Length"
              type="number"
              value={formik.values.passwordMinLength}
              onChange={formik.handleChange}
              size="small"
            />
          </Grid>
          
          <Grid item xs={12} md={6}>
            <FormControlLabel
              control={
                <Switch
                  name="passwordRequireSpecial"
                  checked={formik.values.passwordRequireSpecial}
                  onChange={formik.handleChange}
                />
              }
              label="Require Special Characters in Passwords"
            />
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="enableAuditLog"
                  checked={formik.values.enableAuditLog}
                  onChange={formik.handleChange}
                />
              }
              label="Enable Audit Logging"
            />
          </Grid>
          
          <Grid item xs={12}>
            <Button
              type="submit"
              variant="contained"
              startIcon={<SaveIcon />}
              disabled={isLoading}
            >
              Save Security Settings
            </Button>
          </Grid>
        </Grid>
      </Box>
    );
  };

  const APISettings = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">API Keys</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleCreateApiKey}
        >
          New API Key
        </Button>
      </Box>
      
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Key</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Expires</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {apiKeys.map((key) => (
              <TableRow key={key.id}>
                <TableCell>{key.name}</TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography
                      variant="caption"
                      sx={{
                        fontFamily: 'monospace',
                        backgroundColor: 'background.default',
                        p: 0.5,
                        borderRadius: 0.5,
                        flexGrow: 1,
                      }}
                    >
                      {showApiKey[key.id] ? key.key : '••••••••••••••••'}
                    </Typography>
                    <Tooltip title={showApiKey[key.id] ? "Hide Key" : "Show Key"}>
                      <IconButton
                        size="small"
                        onClick={() => setShowApiKey({
                          ...showApiKey,
                          [key.id]: !showApiKey[key.id]
                        })}
                      >
                        {showApiKey[key.id] ? <ViewOffIcon /> : <ViewIcon />}
                      </IconButton>
                    </Tooltip>
                  </Box>
                </TableCell>
                <TableCell>
                  {new Date(key.created_at).toLocaleDateString()}
                </TableCell>
                <TableCell>
                  {key.expires_at ? new Date(key.expires_at).toLocaleDateString() : 'Never'}
                </TableCell>
                <TableCell>
                  <Chip
                    label={key.is_active ? 'Active' : 'Inactive'}
                    color={key.is_active ? 'success' : 'error'}
                    size="small"
                  />
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Delete">
                    <IconButton
                      size="small"
                      onClick={() => handleDeleteApiKey(key.id)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      
      <Alert severity="warning" sx={{ mt: 2 }}>
        API keys provide full access to the system. Keep them secure and rotate regularly.
      </Alert>
    </Box>
  );

  const NotificationSettings = () => {
    const formik = useFormik({
      initialValues: {
        enableEmailNotifications: settings.enable_email_notifications || false,
        smtpHost: settings.smtp_host || '',
        smtpPort: settings.smtp_port || 587,
        smtpUsername: settings.smtp_username || '',
        smtpPassword: settings.smtp_password || '',
        notificationEmail: settings.notification_email || '',
        enableWebhook: settings.enable_webhook || false,
        webhookUrl: settings.webhook_url || '',
      },
      onSubmit: handleSaveSettings,
      enableReinitialize: true,
    });

    return (
      <Box component="form" onSubmit={formik.handleSubmit}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Typography variant="subtitle1" gutterBottom>
              Email Notifications
            </Typography>
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="enableEmailNotifications"
                  checked={formik.values.enableEmailNotifications}
                  onChange={formik.handleChange}
                />
              }
              label="Enable Email Notifications"
            />
          </Grid>
          
          {formik.values.enableEmailNotifications && (
            <>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  name="smtpHost"
                  label="SMTP Host"
                  value={formik.values.smtpHost}
                  onChange={formik.handleChange}
                  size="small"
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  name="smtpPort"
                  label="SMTP Port"
                  type="number"
                  value={formik.values.smtpPort}
                  onChange={formik.handleChange}
                  size="small"
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  name="smtpUsername"
                  label="SMTP Username"
                  value={formik.values.smtpUsername}
                  onChange={formik.handleChange}
                  size="small"
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  name="smtpPassword"
                  label="SMTP Password"
                  type="password"
                  value={formik.values.smtpPassword}
                  onChange={formik.handleChange}
                  size="small"
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  name="notificationEmail"
                  label="Notification Email"
                  value={formik.values.notificationEmail}
                  onChange={formik.handleChange}
                  size="small"
                />
              </Grid>
            </>
          )}
          
          <Grid item xs={12}>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle1" gutterBottom>
              Webhook Notifications
            </Typography>
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  name="enableWebhook"
                  checked={formik.values.enableWebhook}
                  onChange={formik.handleChange}
                />
              }
              label="Enable Webhook Notifications"
            />
          </Grid>
          
          {formik.values.enableWebhook && (
            <Grid item xs={12}>
              <TextField
                fullWidth
                name="webhookUrl"
                label="Webhook URL"
                value={formik.values.webhookUrl}
                onChange={formik.handleChange}
                size="small"
                placeholder="https://your-webhook.com/endpoint"
              />
            </Grid>
          )}
          
          <Grid item xs={12}>
            <Button
              type="submit"
              variant="contained"
              startIcon={<SaveIcon />}
              disabled={isLoading}
            >
              Save Notification Settings
            </Button>
          </Grid>
        </Grid>
      </Box>
    );
  };

  const [commandTemplates, setCommandTemplates] = useState([]);

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const data = await SettingsService.getCommandTemplates();
      setCommandTemplates(data || []);
    } catch (error) {
      // ignore, not critical
    }
  };

  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState(null);

  const handleCreateTemplate = async () => {
    setEditingTemplate({ name: '', value: '', template: '', description: '', is_public: false });
    setEditDialogOpen(true);
  };

  const handleOpenEdit = (tmpl) => {
    setEditingTemplate({ ...tmpl });
    setEditDialogOpen(true);
  };

  const handleSaveTemplate = async (updated) => {
    try {
      let saved;
      if (updated.id) {
        saved = await SettingsService.updateCommandTemplate(updated.id, updated);
        setCommandTemplates(commandTemplates.map((t) => (t.id === saved.id ? saved : t)));
        enqueueSnackbar('Template updated', { variant: 'success' });
      } else {
        saved = await SettingsService.createCommandTemplate(updated);
        setCommandTemplates([...commandTemplates, saved]);
        enqueueSnackbar('Template created', { variant: 'success' });
      }
      setEditDialogOpen(false);
      setEditingTemplate(null);
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to save template'), { variant: 'error' });
    }
  };

  const handleDeleteTemplate = async (id) => {
    if (!window.confirm('Delete this template?')) return;
    try {
      await SettingsService.deleteCommandTemplate(id);
      setCommandTemplates(commandTemplates.filter(t => t.id !== id));
      enqueueSnackbar('Template deleted', { variant: 'success' });
    } catch (error) {
      enqueueSnackbar(SettingsService.getErrorMessage(error, 'Failed to delete template'), { variant: 'error' });
    }
  };

  const tabs = [
    { label: 'General', icon: <SettingsIcon />, component: <GeneralSettings /> },
    { label: 'Security', icon: <SecurityIcon />, component: <SecuritySettings /> },
    { label: 'API', icon: <KeyIcon />, component: <APISettings /> },
    { label: 'Notifications', icon: <NotificationsIcon />, component: <NotificationSettings /> },
    { label: 'Command Templates', icon: <CodeIcon />, component: (
      <Box>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">Command Templates</Typography>
          <Box>
            <Button startIcon={<AddIcon />} onClick={handleCreateTemplate}>Create Template</Button>
          </Box>
        </Box>

        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Command</TableCell>
                <TableCell>Arguments</TableCell>
                <TableCell>Created By</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {commandTemplates.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>{t.name}</TableCell>
                  <TableCell>{t.value}</TableCell>
                  <TableCell>{t.template}</TableCell>
                  <TableCell>{t.created_by || 'system'}</TableCell>
                  <TableCell align="right">
                    <Tooltip title="Edit">
                      <IconButton size="small" onClick={() => handleOpenEdit(t)}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton size="small" onClick={() => handleDeleteTemplate(t.id)}>
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Preview">
                      <IconButton size="small" onClick={() => { alert(t.template || '(empty)'); }}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    ) },
  ];

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" fontWeight="bold">
          System Settings
        </Typography>
        <Tooltip title="Refresh">
          <IconButton onClick={loadSettings} disabled={isLoading}>
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Box>

      {isLoading && <LinearProgress sx={{ mb: 2 }} />}

      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={(e, v) => setTabValue(v)}
          variant="scrollable"
          scrollButtons="auto"
        >
          {tabs.map((tab, index) => (
            <Tab key={index} label={tab.label} icon={tab.icon} iconPosition="start" />
          ))}
        </Tabs>
        
        <Divider />
        
        <Box sx={{ p: 3 }}>
          {tabs[tabValue].component}
        </Box>
      </Paper>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <StorageIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Database Information
              </Typography>
              <Box sx={{ '& > *': { mb: 1 } }}>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Type:</Typography>
                  <Typography>PostgreSQL</Typography>
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Agents:</Typography>
                  <Typography>{settings.agent_count || 0}</Typography>
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Tasks:</Typography>
                  <Typography>{settings.task_count || 0}</Typography>
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Files:</Typography>
                  <Typography>{settings.file_count || 0}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <CodeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                System Information
              </Typography>
              <Box sx={{ '& > *': { mb: 1 } }}>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Version:</Typography>
                  <Typography>1.0.0</Typography>
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Uptime:</Typography>
                  <Typography>{settings.uptime || '0s'}</Typography>
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Memory Usage:</Typography>
                  <Typography>{settings.memory_usage || '0 MB'}</Typography>
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography color="textSecondary">Last Backup:</Typography>
                  <Typography>{settings.last_backup || 'Never'}</Typography>
                </Box>
              </Box>
              <Button
                variant="outlined"
                fullWidth
                sx={{ mt: 2 }}
                onClick={() => {
                  if (window.confirm('Are you sure you want to restart the system?')) {
                    enqueueSnackbar('System restart initiated', { variant: 'info' });
                  }
                }}
              >
                Restart System
              </Button>
            </CardContent>
          </Card>

          {/* Edit template dialog */}
          <Dialog open={editDialogOpen} onClose={() => { setEditDialogOpen(false); setEditingTemplate(null); }} fullWidth maxWidth="sm">
            <DialogTitle>{editingTemplate?.id ? 'Edit Template' : 'Create Template'}</DialogTitle>
            <DialogContent>
              {editingTemplate && (
                <Box sx={{ '& > *': { mb: 2 } }}>
                  <TextField fullWidth label="Name" value={editingTemplate.name} onChange={(e) => setEditingTemplate({ ...editingTemplate, name: e.target.value })} />
                  <TextField fullWidth label="Command (value)" value={editingTemplate.value} onChange={(e) => setEditingTemplate({ ...editingTemplate, value: e.target.value })} />
                  <TextField fullWidth label="Arguments / Template" value={editingTemplate.template} onChange={(e) => setEditingTemplate({ ...editingTemplate, template: e.target.value })} />
                  <TextField fullWidth label="Description" value={editingTemplate.description || ''} onChange={(e) => setEditingTemplate({ ...editingTemplate, description: e.target.value })} />
                  <FormGroup>
                    <MUIFormControlLabel control={<Switch checked={!!editingTemplate.is_public} onChange={(e) => setEditingTemplate({ ...editingTemplate, is_public: e.target.checked })} />} label="Public" />
                  </FormGroup>
                </Box>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => { setEditDialogOpen(false); setEditingTemplate(null); }}>Cancel</Button>
              <Button onClick={() => handleSaveTemplate(editingTemplate)} variant="contained">Save</Button>
            </DialogActions>
          </Dialog>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Settings;
