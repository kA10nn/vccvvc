import apiClient, { extractErrorMessage } from './apiClient';

/**
 * @typedef {Object} Agent
 * @property {number} id
 * @property {string} uuid
 * @property {string} hostname
 * @property {string} username
 * @property {string} os
 * @property {string} arch
 * @property {string} ip_address
 * @property {string} status
 * @property {string} last_seen
 */

/**
 * @typedef {Object} Task
 * @property {number} id
 * @property {number} agent_id
 * @property {string} command
 * @property {string} arguments
 * @property {string} status
 * @property {string} output
 */

/**
 * @typedef {Object} FileRecord
 * @property {number} id
 * @property {number} agent_id
 * @property {string} filename
 * @property {string} file_path
 * @property {number} file_size
 * @property {string} uploaded_at
 */

const AgentService = {
  // Auth
  login: (credentials) =>
    apiClient.post('/auth/login', credentials).then((res) => {
      if (res.data?.token) {
        localStorage.setItem('token', res.data.token);
      }
      if (res.data?.user) {
        localStorage.setItem('user', JSON.stringify(res.data.user));
      }
      return res.data;
    }),

  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    return Promise.resolve();
  },

  // Agents
  /** @returns {Promise<Agent[]>} */
  getAgents: () => apiClient.get('/agents').then((res) => res.data),

  /** @returns {Promise<Agent>} */
  getAgent: (id) => apiClient.get(`/agents/${id}`).then((res) => res.data),

  deleteAgent: (id) => apiClient.delete(`/agents/${id}`),

  // Tasks
  /** @returns {Promise<Task[]|{items: Task[], page: number, page_size: number, total: number}>} */
  getTasks: (params = {}) =>
    apiClient.get('/tasks', { params }).then((res) => res.data),

  /** @returns {Promise<Task>} */
  getTask: (id) => apiClient.get(`/tasks/${id}`).then((res) => res.data),

  createTask: (agentId, command, args = '') =>
    apiClient
      .post('/tasks', { agent_id: agentId, command, arguments: args })
      .then((res) => res.data),

  cancelTask: (id) => apiClient.post(`/tasks/${id}/cancel`),

  // Files
  uploadFile: (agentId, file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('agent_id', agentId);

    return apiClient
      .post('/files/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (onProgress && progressEvent.total) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            onProgress(percentCompleted);
          }
        },
      })
      .then((res) => res.data);
  },

  /** @returns {Promise<FileRecord[]>} */
  getFiles: (agentId) =>
    apiClient.get(`/agents/${agentId}/files`).then((res) => res.data),

  downloadFile: (fileId) =>
    apiClient.get(`/files/${fileId}/download`, { responseType: 'blob' }),

  deleteFile: (fileId) => apiClient.delete(`/files/${fileId}`),

  // System
  getSystemInfo: () => apiClient.get('/system/info').then((res) => res.data),

  getActivity: (limit = 50) =>
    apiClient.get('/activity', { params: { limit } }).then((res) => res.data),

  // Commands
  executeCommand: (agentId, command) =>
    apiClient.post(`/agents/${agentId}/execute`, { command }).then((res) => res.data),

  getShell: (agentId) =>
    apiClient.get(`/agents/${agentId}/shell`).then((res) => res.data),

  // Settings
  getSettings: () => apiClient.get('/settings').then((res) => res.data),

  updateSettings: (settings) =>
    apiClient.put('/settings', settings).then((res) => res.data),

  // Health
  healthCheck: () => apiClient.get('/health').then((res) => res.data),

  getErrorMessage: (error, fallback) => extractErrorMessage(error, fallback),
};

export default AgentService;
