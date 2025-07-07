import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import ThreatList from '../ThreatList'; // Changed from '../ThreatList' to '../ThreatList'
import { threatAPI } from '../../api';

// Mock the API module
vi.mock('../../api', () => ({
  threatAPI: {
    getCategories: vi.fn(),
    getThreats: vi.fn()
  }
}));

// Type the mocked functions
const mockThreatAPI = threatAPI as any;

const sampleCategories = ['Malware', 'Phishing'];

const sampleThreatsPage1 = [
  { id: 1, description: 'Threat1', category: 'Malware', severity: 'High' },
  { id: 2, description: 'Threat2', category: 'Malware', severity: 'Medium' },
  { id: 3, description: 'Threat3', category: 'Phishing', severity: 'Low' },
  { id: 4, description: 'Threat4', category: 'Malware', severity: 'Critical' },
  { id: 5, description: 'Threat5', category: 'Phishing', severity: 'High' },
  { id: 6, description: 'Threat6', category: 'Malware', severity: 'Medium' },
  { id: 7, description: 'Threat7', category: 'Phishing', severity: 'Low' },
  { id: 8, description: 'Threat8', category: 'Malware', severity: 'High' },
  { id: 9, description: 'Threat9', category: 'Phishing', severity: 'Critical' },
  { id: 10, description: 'Threat10', category: 'Malware', severity: 'Medium' }
];

const sampleThreatsPage2 = [
  { id: 11, description: 'Threat11', category: 'Phishing', severity: 'Low' },
  { id: 12, description: 'Threat12', category: 'Malware', severity: 'High' }
];

describe('ThreatList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset all mocks to avoid interference between tests
    mockThreatAPI.getCategories.mockReset();
    mockThreatAPI.getThreats.mockReset();
  });

  it('shows loading spinner then displays threat items', async () => {
    // Setup mocks
    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats.mockResolvedValue(sampleThreatsPage1);

    render(<ThreatList />);

    // Check for loading spinner - look for the spinning div
    const spinner = screen.getByRole('status');
    expect(spinner).toBeInTheDocument();

    // Wait for threats to load
    await waitFor(() => {
      expect(screen.getByText(/Threat1/i)).toBeInTheDocument();
    });

    // Check that categories are loaded in the dropdown
    await waitFor(() => {
      sampleCategories.forEach(cat => {
        expect(screen.getByRole('option', { name: cat })).toBeInTheDocument();
      });
    });

    // Verify API calls were made
    expect(mockThreatAPI.getCategories).toHaveBeenCalledTimes(1);
    expect(mockThreatAPI.getThreats).toHaveBeenCalledWith({
      page: 1,
      limit: 10,
      search: '',
      category: ''
    });
  });

  it('displays error message and allows retry', async () => {
    // Setup mocks
    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats.mockRejectedValue(new Error('API Error'));

    render(<ThreatList />);

    // Wait for error message to appear
    await waitFor(() => {
      expect(screen.getByText(/Failed to fetch threats/i)).toBeInTheDocument();
    });

    // Find and click retry button
    const retryButton = screen.getByRole('button', { name: /Retry/i });
    fireEvent.click(retryButton);

    // Verify API was called again
    expect(mockThreatAPI.getThreats).toHaveBeenCalledTimes(2);
  });

  it('handles pagination correctly', async () => {
    // Setup mocks for pagination
    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats
      .mockResolvedValueOnce(sampleThreatsPage1)
      .mockResolvedValueOnce(sampleThreatsPage2);

    render(<ThreatList />);

    // Wait for first page to load
    await waitFor(() => {
      expect(screen.getByText(/Threat1/)).toBeInTheDocument();
    });

    // Click next button
    const nextButton = screen.getByRole('button', { name: /Next/i });
    fireEvent.click(nextButton);

    // Wait for second page to load
    await waitFor(() => {
      expect(screen.getByText(/Threat11/)).toBeInTheDocument();
    });

    // Verify API was called with page 2
    expect(mockThreatAPI.getThreats).toHaveBeenCalledWith({
      page: 2,
      limit: 10,
      search: '',
      category: ''
    });

    // Click previous button
    const prevButton = screen.getByRole('button', { name: /Previous/i });
    fireEvent.click(prevButton);

    // Wait for first page to load again
    await waitFor(() => {
      expect(screen.getByText(/Threat1/)).toBeInTheDocument();
    });
  });

  it('handles search functionality', async () => {
    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats.mockResolvedValue(sampleThreatsPage1);

    render(<ThreatList />);

    // Wait for component to load
    await waitFor(() => {
      expect(screen.getByText(/Threat1/)).toBeInTheDocument();
    });

    // Find search input and type
    const searchInput = screen.getByPlaceholderText(/Search threats/i);
    fireEvent.change(searchInput, { target: { value: 'malware' } });

    // Wait for debounced search (300ms + some buffer)
    await waitFor(() => {
      expect(mockThreatAPI.getThreats).toHaveBeenCalledWith({
        page: 1,
        limit: 10,
        search: 'malware',
        category: ''
      });
    }, { timeout: 1000 });
  });

  it('handles category filter', async () => {
    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats.mockResolvedValue(sampleThreatsPage1);

    render(<ThreatList />);

    // Wait for component to load
    await waitFor(() => {
      expect(screen.getByText(/Threat1/)).toBeInTheDocument();
    });

    // Find category select and change value
    const categorySelect = screen.getByRole('combobox');
    fireEvent.change(categorySelect, { target: { value: 'Malware' } });

    // Wait for API call with category filter
    await waitFor(() => {
      expect(mockThreatAPI.getThreats).toHaveBeenCalledWith({
        page: 1,
        limit: 10,
        search: '',
        category: 'Malware'
      });
    });
  });

  it('displays no threats message when list is empty', async () => {
    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats.mockResolvedValue([]);

    render(<ThreatList />);

    // Wait for empty state message
    await waitFor(() => {
      expect(screen.getByText(/No threats found matching your criteria/i)).toBeInTheDocument();
    });
  });

  it('displays correct severity colors', async () => {
    const threatsWithDifferentSeverities = [
      { id: 1, description: 'Critical Threat', category: 'Malware', severity: 'Critical' },
      { id: 2, description: 'High Threat', category: 'Malware', severity: 'High' },
      { id: 3, description: 'Medium Threat', category: 'Malware', severity: 'Medium' },
      { id: 4, description: 'Low Threat', category: 'Malware', severity: 'Low' }
    ];

    mockThreatAPI.getCategories.mockResolvedValue(sampleCategories);
    mockThreatAPI.getThreats.mockResolvedValue(threatsWithDifferentSeverities);

    render(<ThreatList />);

    // Wait for threats to load
    await waitFor(() => {
      expect(screen.getByText(/Critical Threat/)).toBeInTheDocument();
    });

    // Check that severity badges are displayed
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
    expect(screen.getByText('Low')).toBeInTheDocument();
  });
});