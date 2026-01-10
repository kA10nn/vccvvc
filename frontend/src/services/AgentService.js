import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api/v1';

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('ares_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const AgentService = {
  // Agent operations
  getAgents: () => axiosInstance.get('/agents').then(res => res.data),
  
  getAgent: (uuid) => axiosInstance.get(`/agents/${uuid}`).then(res => res.data),
  
  deleteAgent: (uuid) => axiosInstance.delete(`/agents/${uuid}`),
  
  getAgentTasks: (uuid) => axiosInstance.get(`/agents/${uuid}/tasks`).then(res => res.data),
  
  // Task operations
  createTask: (agentId, command, args) =>
    axiosInstance.post(`/agents/${agentId}/tasks`, { command, args }).then(res => res.data),
  
  getTasks: () => axiosInstance.get('/tasks').then(res => res.data),
  
  cancelTask: (taskId) => axiosInstance.post(`/tasks/${taskId}/cancel`),
  
  // File operations
  uploadFile: (agentId, file) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('agent_id', agentId);
    
    return axiosInstance.post('/files/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },
  
  downloadFile: (fileId) =>
    axiosInstance.get(`/files/${fileId}/download`, { responseType: 'blob' }),
  
  getFiles: (agentId) =>
    axiosInstance.get(`/agents/${agentId}/files`).then(res => res.data),
  
  // System operations
  getStats: () => axiosInstance.get('/stats').then(res => res.data),
  
  getRecentActivity: () => axiosInstance.get('/activity/recent').then(res => res.data),
  
  // Authentication
  login: (username, password) =>
    axiosInstance.post('/auth/login', { username, password }).then(res => {
      if (res.data.token) {
        localStorage.setItem('ares_token', res.data.token);
        localStorage.setItem('ares_user', JSON.stringify(res.data.user));
      }
      return res.data;
    }),
  
  logout: () => {
    localStorage.removeItem('ares_token');
    localStorage.removeItem('ares_user');
    return axiosInstance.post('/auth/logout');
  },
  
  // WebSocket helper
  getWebSocketUrl: () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/ws`;
  }
};

export default AgentService;
