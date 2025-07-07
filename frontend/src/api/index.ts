// API types and functions
export interface ThreatQueryParams {
  page: number;
  limit: number;
  search: string;
  category: string;
}

export interface Threat {
  id: number;
  description: string;
  category: string;
  severity: string;
}

// Mock API implementation for testing
export const threatAPI = {
  getCategories: async (): Promise<string[]> => {
    // This would normally be a real API call
    return ['Malware', 'Phishing', 'Network Attack', 'Social Engineering'];
  },

  getThreats: async (params: ThreatQueryParams): Promise<Threat[]> => {
    // This would normally be a real API call
    const mockThreats: Threat[] = [
      { id: 1, description: 'Sample threat 1', category: 'Malware', severity: 'High' },
      { id: 2, description: 'Sample threat 2', category: 'Phishing', severity: 'Medium' },
      // Add more mock data as needed
    ];
    return mockThreats;
  }
};