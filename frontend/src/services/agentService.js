import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || '/api/v1';

const axiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth token
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

const AgentService = {
  // Auth
  login: (credentials) => axiosInstance.post('/auth/login', credentials),
  
  logout: () => axiosInstance.post('/auth/logout'),
  
  // Agents
  getAgents: () => axiosInstance.get('/agents').then(res => res.data),
  
  getAgent: (id) => axiosInstance.get(`/agents/${id}`).then(res => res.data),
  
  deleteAgent: (id) => axiosInstance.delete(`/agents/${id}`),
  
  // Tasks
  getTasks: (params = {}) => 
    axiosInstance.get('/tasks', { params }).then(res => res.data),
  
  getTask: (id) => axiosInstance.get(`/tasks/${id}`).then(res => res.data),
  
  createTask: (agentId, command, args = '') =>
    axiosInstance.post(`/agents/${agentId}/tasks`, { command, args }).then(res => res.data),
  
  cancelTask: (id) => axiosInstance.post(`/tasks/${id}/cancel`),
  
  // Files
  uploadFile: (agentId, file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('agent_id', agentId);
    
    return axiosInstance.post('/files/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(percentCompleted);
        }
      },
    }).then(res => res.data);
  },
  
  getFiles: (agentId) => 
    axiosInstance.get(`/agents/${agentId}/files`).then(res => res.data),
  
  downloadFile: (fileId) =>
    axiosInstance.get(`/files/${fileId}/download`, { responseType: 'blob' }),
  
  deleteFile: (fileId) => axiosInstance.delete(`/files/${fileId}`),
  
  // System
  getSystemInfo: () => 
    axiosInstance.get('/system/info').then(res => res.data),
  
  getActivity: (limit = 50) =>
    axiosInstance.get('/activity', { params: { limit } }).then(res => res.data),
  
  // Commands
  executeCommand: (agentId, command) =>
    axiosInstance.post(`/agents/${agentId}/execute`, { command }).then(res => res.data),
  
  getShell: (agentId) =>
    axiosInstance.get(`/agents/${agentId}/shell`).then(res => res.data),
  
  // Settings
  getSettings: () => axiosInstance.get('/settings').then(res => res.data),
  
  updateSettings: (settings) => 
    axiosInstance.put('/settings', settings).then(res => res.data),
  
  // Health
  healthCheck: () => axiosInstance.get('/health').then(res => res.data),
};

export default AgentService;
