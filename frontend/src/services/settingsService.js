import apiClient, { extractErrorMessage } from './apiClient';

const SettingsService = {
  // Get all settings
  getSettings: () => apiClient.get('/settings').then((res) => res.data),

  // Update settings
  updateSettings: (settings) => apiClient.put('/settings', settings),

  // API Keys
  getApiKeys: () => apiClient.get('/settings/api-keys').then((res) => res.data),

  createApiKey: (data) =>
    apiClient.post('/settings/api-keys', data).then((res) => res.data),

  deleteApiKey: (id) => apiClient.delete(`/settings/api-keys/${id}`),

  // Webhooks
  getWebhooks: () => apiClient.get('/settings/webhooks').then((res) => res.data),

  createWebhook: (data) =>
    apiClient.post('/settings/webhooks', data).then((res) => res.data),

  updateWebhook: (id, data) => apiClient.put(`/settings/webhooks/${id}`, data),

  deleteWebhook: (id) => apiClient.delete(`/settings/webhooks/${id}`),

  // System
  getSystemInfo: () => apiClient.get('/settings/system-info').then((res) => res.data),

  restartSystem: () => apiClient.post('/settings/restart'),

  backupSystem: () => apiClient.post('/settings/backup'),

  // Users
  getUsers: () => apiClient.get('/settings/users').then((res) => res.data),

  createUser: (data) => apiClient.post('/settings/users', data).then((res) => res.data),

  updateUser: (id, data) => apiClient.put(`/settings/users/${id}`, data),

  deleteUser: (id) => apiClient.delete(`/settings/users/${id}`),

  // Logs
  getLogs: (params) => apiClient.get('/settings/logs', { params }).then((res) => res.data),

  clearLogs: () => apiClient.delete('/settings/logs'),

  // Export/Import
  exportData: () => apiClient.get('/settings/export', { responseType: 'blob' }),

  importData: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post('/settings/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  getErrorMessage: (error, fallback) => extractErrorMessage(error, fallback),
};

export default SettingsService;
