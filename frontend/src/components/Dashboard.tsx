import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { TrendingUp, Shield, AlertTriangle, Activity, Wifi, WifiOff, RefreshCw } from 'lucide-react';

interface Stats {
  total: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

interface ConnectionStatus {
  connected: boolean;
  testing: boolean;
  error: string | null;
}

// API functions with improved error handling
const API_BASE_URL = 'http://localhost:8000';

const threatAPI = {
  testConnection: async (): Promise<boolean> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/test`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.ok;
    } catch (error) {
      console.error('Connection test failed:', error);
      return false;
    }
  },

  getStats: async (): Promise<Stats> => {
    const response = await fetch(`${API_BASE_URL}/api/stats`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
    }
    
    return response.json();
  },

  getHealth: async (): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return response.json();
  }
};

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({
    connected: false,
    testing: false,
    error: null
  });

  useEffect(() => {
    initializeConnection();
  }, []);

  const initializeConnection = async () => {
    setConnectionStatus(prev => ({ ...prev, testing: true, error: null }));
    
    try {
      const isConnected = await threatAPI.testConnection();
      setConnectionStatus({
        connected: isConnected,
        testing: false,
        error: isConnected ? null : 'Unable to connect to API server'
      });
      
      if (isConnected) {
        await fetchStats();
      }
    } catch (error) {
      setConnectionStatus({
        connected: false,
        testing: false,
        error: 'Connection test failed'
      });
    }
  };

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const data = await threatAPI.getStats();
      setStats(data);
      
      // Update connection status on successful fetch
      setConnectionStatus(prev => ({ ...prev, connected: true, error: null }));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(`Failed to fetch statistics: ${errorMessage}`);
      setConnectionStatus(prev => ({ ...prev, connected: false, error: errorMessage }));
      console.error('Error fetching stats:', err);
    } finally {
      setLoading(false);
    }
  };

  const ConnectionIndicator = () => (
    <div className={`flex items-center space-x-2 ${connectionStatus.connected ? 'text-green-400' : 'text-red-400'}`}>
      {connectionStatus.testing ? (
        <RefreshCw className="h-4 w-4 animate-spin" />
      ) : connectionStatus.connected ? (
        <Wifi className="h-4 w-4" />
      ) : (
        <WifiOff className="h-4 w-4" />
      )}
      <span className="text-sm">
        {connectionStatus.testing ? 'Testing...' : connectionStatus.connected ? 'Connected' : 'Disconnected'}
      </span>
    </div>
  );

  const TroubleshootingCard = () => (
    <div className="bg-yellow-900/20 border border-yellow-500 rounded-lg p-6">
      <div className="flex items-start space-x-3">
        <AlertTriangle className="h-6 w-6 text-yellow-400 mt-1" />
        <div>
          <h3 className="text-lg font-semibold text-yellow-200 mb-2">Connection Issues</h3>
          <p className="text-yellow-100 mb-4">
            {connectionStatus.error || 'Unable to connect to the backend API'}
          </p>
          <div className="space-y-2 text-sm text-yellow-100">
            <p><strong>Troubleshooting steps:</strong></p>
            <ul className="list-disc list-inside space-y-1 ml-4">
              <li>Make sure the backend server is running on <code className="bg-yellow-800 px-1 rounded">http://localhost:8000</code></li>
              <li>Run <code className="bg-yellow-800 px-1 rounded">python main.py</code> or <code className="bg-yellow-800 px-1 rounded">uvicorn main:app --reload</code> in your backend directory</li>
              <li>Check if port 8000 is available and not blocked by firewall</li>
              <li>Verify CORS settings in the backend</li>
            </ul>
          </div>
          <div className="mt-4 space-x-2">
            <button
              onClick={initializeConnection}
              disabled={connectionStatus.testing}
              className="bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-800 text-white px-4 py-2 rounded-md transition-colors"
            >
              {connectionStatus.testing ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              onClick={fetchStats}
              disabled={loading || connectionStatus.testing}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-4 py-2 rounded-md transition-colors"
            >
              Retry Fetch
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  // Loading state
  if (loading && !stats) {
    return (
      <div className="min-h-screen bg-gray-900 p-6">
        <div className="flex flex-col items-center justify-center h-64 space-y-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400"></div>
          <p className="text-gray-400">Loading dashboard...</p>
          <ConnectionIndicator />
        </div>
      </div>
    );
  }

  // Error or disconnected state
  if (!connectionStatus.connected || error) {
    return (
      <div className="min-h-screen bg-gray-900 p-6">
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-3xl font-bold text-white">Threat Intelligence Dashboard</h2>
            <ConnectionIndicator />
          </div>
          <TroubleshootingCard />
        </div>
      </div>
    );
  }

  // No stats available
  if (!stats) {
    return (
      <div className="min-h-screen bg-gray-900 p-6">
        <div className="text-center text-gray-400">
          <Shield className="h-12 w-12 mx-auto mb-4" />
          <p>No statistics available</p>
          <ConnectionIndicator />
        </div>
      </div>
    );
  }

  // Prepare chart data
  const categoryData = Object.entries(stats.by_category).map(([category, count]) => ({
    category,
    count,
  }));

  const severityData = Object.entries(stats.by_severity).map(([severity, count]) => ({
    severity,
    count,
  }));

  const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h2 className="text-3xl font-bold text-white">Threat Intelligence Dashboard</h2>
          <div className="flex items-center space-x-4">
            <ConnectionIndicator />
            <button
              onClick={fetchStats}
              disabled={loading}
              className="flex items-center bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-4 py-2 rounded-md transition-colors"
            >
              <Activity className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Shield className="h-8 w-8 text-blue-400" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-400">Total Threats</p>
                <p className="text-2xl font-bold text-white">{stats.total.toLocaleString()}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <TrendingUp className="h-8 w-8 text-green-400" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-400">Categories</p>
                <p className="text-2xl font-bold text-white">{Object.keys(stats.by_category).length}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-8 w-8 text-yellow-400" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-400">Severity Levels</p>
                <p className="text-2xl font-bold text-white">{Object.keys(stats.by_severity).length}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Category Distribution */}
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-4">Threats by Category</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={categoryData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="category" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '6px',
                    color: '#F9FAFB'
                  }}
                />
                <Bar dataKey="count" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Severity Distribution */}
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ severity, percent }) => `${severity} (${(percent * 100).toFixed(0)}%)`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '6px',
                    color: '#F9FAFB'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;