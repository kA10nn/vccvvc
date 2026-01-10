import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || '/api/v1';

const axiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
});

axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const SettingsService = {
  // Get all settings
  getSettings: () => axiosInstance.get('/settings').then(res => res.data),
  
  // Update settings
  updateSettings: (settings) => axiosInstance.put('/settings', settings),
  
  // API Keys
  getApiKeys: () => axiosInstance.get('/settings/api-keys').then(res => res.data),
  
  createApiKey: (data) => axiosInstance.post('/settings/api-keys', data).then(res => res.data),
  
  deleteApiKey: (id) => axiosInstance.delete(`/settings/api-keys/${id}`),
  
  // Webhooks
  getWebhooks: () => axiosInstance.get('/settings/webhooks').then(res => res.data),
  
  createWebhook: (data) => axiosInstance.post('/settings/webhooks', data).then(res => res.data),
  
  updateWebhook: (id, data) => axiosInstance.put(`/settings/webhooks/${id}`, data),
  
  deleteWebhook: (id) => axiosInstance.delete(`/settings/webhooks/${id}`),
  
  // System
  getSystemInfo: () => axiosInstance.get('/settings/system-info').then(res => res.data),
  
  restartSystem: () => axiosInstance.post('/settings/restart'),
  
  backupSystem: () => axiosInstance.post('/settings/backup'),
  
  // Users
  getUsers: () => axiosInstance.get('/settings/users').then(res => res.data),
  
  createUser: (data) => axiosInstance.post('/settings/users', data).then(res => res.data),
  
  updateUser: (id, data) => axiosInstance.put(`/settings/users/${id}`, data),
  
  deleteUser: (id) => axiosInstance.delete(`/settings/users/${id}`),
  
  // Logs
  getLogs: (params) => axiosInstance.get('/settings/logs', { params }).then(res => res.data),
  
  clearLogs: () => axiosInstance.delete('/settings/logs'),
  
  // Export/Import
  exportData: () => axiosInstance.get('/settings/export', { responseType: 'blob' }),
  
  importData: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return axiosInstance.post('/settings/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
};

export default SettingsService;
