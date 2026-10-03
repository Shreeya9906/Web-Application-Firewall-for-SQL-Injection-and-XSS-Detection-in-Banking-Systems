import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:5000/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json'
  }
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.data?.message) {
      error.message = error.response.data.message;
    }
    return Promise.reject(error);
  }
);

export const login = (username, password) => api.post('/login', { username, password });
export const register = (data) => api.post('/register', data);
export const logout = () => api.post('/logout');
export const getMe = () => api.get('/me');
export const getDashboard = () => api.get('/dashboard');
export const getAccounts = () => api.get('/accounts');
export const getAccountDetails = (id) => api.get(`/accounts/${id}`);
export const getTransactions = (type) => api.get(type ? `/transactions?transaction_type=${type}` : '/transactions');
export const transfer = (data) => api.post('/transfer', data);
export const getBeneficiaries = () => api.get('/beneficiaries');
export const addBeneficiary = (data) => api.post('/beneficiaries', data);
export const getSecuritySummary = () => api.get('/security/summary');
export const getSecurityEvents = (params = {}) => api.get('/security/events', { params });
export const getAttackDistribution = () => api.get('/security/attack-distribution');
export const getSecurityTrends = (params = {}) => api.get('/security/trends', { params });
export const getDetectionSummary = () => api.get('/security/detection-summary');
export const getBehaviorAlerts = () => api.get('/security/behavior-alerts');
export const reviewSecurityEvent = (eventId, status) => api.patch(`/security/events/${eventId}/review`, { status });
export const getAdaptiveRules = () => api.get('/security/adaptive-rules');
export const reviewAdaptiveRule = (ruleId, status) => api.patch(`/security/adaptive-rules/${ruleId}`, { status });

export default api;
