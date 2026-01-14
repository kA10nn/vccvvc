let axios = require('axios');
if (axios && axios.default) axios = axios.default;

const API_BASE = process.env.REACT_APP_API_URL || '/api/v1';

export const extractErrorMessage = (error, fallback = 'Request failed') => {
  if (!error) return fallback;
  if (typeof error === 'string') return error;

  const data = error.response?.data;
  if (typeof data === 'string') return data;
  if (data?.error) return data.error;
  if (data?.message) return data.message;
  if (error.message) return error.message;

  return fallback;
};

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    error.message = extractErrorMessage(error, error.message);
    return Promise.reject(error);
  }
);

export default apiClient;
