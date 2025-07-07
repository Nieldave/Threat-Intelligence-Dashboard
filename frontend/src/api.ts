import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for logging
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => Promise.reject(error)
);

// Add response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// API Functions
export const threatAPI = {
  // Get paginated threats with search and filtering
  getThreats: async (params: {
    page?: number;
    limit?: number;
    search?: string;
    category?: string;
  }) => {
    const { data } = await api.get('/api/threats', { params });
    return data;
  },

  // Get single threat by ID
  getThreat: async (id: string) => {
    const { data } = await api.get(`/api/threats/${id}`);
    return data;
  },

  // Get threat statistics
  getStats: async () => {
    const { data } = await api.get('/api/threats/stats');
    return data;
  },

  // Get categories
  getCategories: async () => {
    const { data } = await api.get('/api/categories');
    return data;
  },

  // Analyze threat description (placeholder - not implemented in backend yet)
  analyzeThreat: async (description: string) => {
    // Since this endpoint doesn't exist yet, we'll return a mock response
    // You can implement this in your backend later
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          predicted_category: 'Malware',
          confidence: 0.85
        });
      }, 1000);
    });
  },

  // Health check
  checkHealth: async () => {
    const { data } = await api.get('/health');
    return data;
  },
};

export default api;