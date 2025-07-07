// ThreatAnalyzer.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ThreatAnalyzer from '../components/ThreatAnalyzer';
import { threatAPI } from '../api';

// Mock the API
jest.mock('../api', () => ({
  threatAPI: {
    analyzeThreat: jest.fn()
  }
}));

const mockThreatAPI = threatAPI as jest.Mocked<typeof threatAPI>;

describe('ThreatAnalyzer', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders header and disabled button initially', () => {
    render(<ThreatAnalyzer />);
    
    expect(screen.getByText(/Threat Analyzer/i)).toBeInTheDocument();
    expect(screen.getByText(/Use machine learning to analyze and categorize threat descriptions/i)).toBeInTheDocument();
    
    const analyzeButton = screen.getByRole('button', { name: /Analyze Threat/i });
    expect(analyzeButton).toBeDisabled();
  });

  test('enables button when text is entered', () => {
    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    const analyzeButton = screen.getByRole('button', { name: /Analyze Threat/i });
    
    // Initially disabled
    expect(analyzeButton).toBeDisabled();
    
    // Type some text
    fireEvent.change(textarea, { target: { value: 'Some threat description' }});
    
    // Should now be enabled
    expect(analyzeButton).not.toBeDisabled();
  });

  test('shows validation error on empty submit', async () => {
    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    const analyzeButton = screen.getByRole('button', { name: /Analyze Threat/i });
    
    // Add some text then remove it to trigger the empty validation
    fireEvent.change(textarea, { target: { value: 'test' }});
    fireEvent.change(textarea, { target: { value: '' }});
    
    // Try to submit
    fireEvent.click(analyzeButton);
    
    await waitFor(() => {
      expect(screen.getByText(/Please enter a threat description/i)).toBeInTheDocument();
    });
  });

  test('shows loading state and then result on success', async () => {
    mockThreatAPI.analyzeThreat.mockResolvedValue({
      predicted_category: 'Malware',
      confidence: 0.85
    });

    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    const analyzeButton = screen.getByRole('button', { name: /Analyze Threat/i });
    
    // Enter some text
    fireEvent.change(textarea, { target: { value: 'Suspicious executable file with encryption capabilities' }});
    
    // Click analyze
    fireEvent.click(analyzeButton);

    // Should show loading state
    expect(screen.getByText(/Analyzing\.\.\./i)).toBeInTheDocument();
    expect(analyzeButton).toBeDisabled();

    // Wait for the result panel
    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/i)).toBeInTheDocument();
    });
    
    expect(screen.getByText('Malware')).toBeInTheDocument();
    expect(screen.getByText(/85\.0%/i)).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument(); // Confidence level
  });

  test('shows error banner on API failure', async () => {
    mockThreatAPI.analyzeThreat.mockRejectedValue(new Error('API Error'));

    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    const analyzeButton = screen.getByRole('button', { name: /Analyze Threat/i });
    
    // Enter some text
    fireEvent.change(textarea, { target: { value: 'Test threat description' }});
    
    // Click analyze
    fireEvent.click(analyzeButton);

    // Wait for error message
    await waitFor(() => {
      expect(screen.getByText(/Failed to analyze threat/i)).toBeInTheDocument();
    });
  });

  test('displays character count correctly', () => {
    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    
    // Initially shows 0/1000
    expect(screen.getByText('0/1000 characters')).toBeInTheDocument();
    
    // Type some text
    const testText = 'This is a test threat description';
    fireEvent.change(textarea, { target: { value: testText }});
    
    // Should show updated count
    expect(screen.getByText(`${testText.length}/1000 characters`)).toBeInTheDocument();
  });

  test('displays confidence levels correctly', async () => {
    // Test high confidence
    mockThreatAPI.analyzeThreat.mockResolvedValue({
      predicted_category: 'Malware',
      confidence: 0.9
    });

    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    fireEvent.change(textarea, { target: { value: 'High confidence test' }});
    fireEvent.click(screen.getByRole('button', { name: /Analyze Threat/i }));

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/i)).toBeInTheDocument();
    });
    
    expect(screen.getByText('High')).toBeInTheDocument(); // Confidence level
    expect(screen.getByText(/90\.0%/i)).toBeInTheDocument();
  });

  test('displays medium confidence correctly', async () => {
    mockThreatAPI.analyzeThreat.mockResolvedValue({
      predicted_category: 'Phishing',
      confidence: 0.7
    });

    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    fireEvent.change(textarea, { target: { value: 'Medium confidence test' }});
    fireEvent.click(screen.getByRole('button', { name: /Analyze Threat/i }));

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/i)).toBeInTheDocument();
    });
    
    expect(screen.getByText('Medium')).toBeInTheDocument(); // Confidence level
    expect(screen.getByText(/70\.0%/i)).toBeInTheDocument();
  });

  test('displays low confidence correctly', async () => {
    mockThreatAPI.analyzeThreat.mockResolvedValue({
      predicted_category: 'Network Attack',
      confidence: 0.4
    });

    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    fireEvent.change(textarea, { target: { value: 'Low confidence test' }});
    fireEvent.click(screen.getByRole('button', { name: /Analyze Threat/i }));

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/i)).toBeInTheDocument();
    });
    
    expect(screen.getByText('Low')).toBeInTheDocument(); // Confidence level
    expect(screen.getByText(/40\.0%/i)).toBeInTheDocument();
  });

  test('renders example descriptions section', () => {
    render(<ThreatAnalyzer />);
    
    expect(screen.getByText(/Example Descriptions/i)).toBeInTheDocument();
    expect(screen.getByText('Malware')).toBeInTheDocument();
    expect(screen.getByText('Phishing')).toBeInTheDocument();
    expect(screen.getByText('Network Attack')).toBeInTheDocument();
    expect(screen.getByText('Data Breach')).toBeInTheDocument();
  });

  test('renders ML model integration info banner', () => {
    render(<ThreatAnalyzer />);
    
    expect(screen.getByText(/ML Model Integration/i)).toBeInTheDocument();
    expect(screen.getByText(/shows demo predictions/i)).toBeInTheDocument();
  });

  test('clears error when starting new analysis', async () => {
    // First, cause an error
    mockThreatAPI.analyzeThreat.mockRejectedValue(new Error('API Error'));

    render(<ThreatAnalyzer />);
    
    const textarea = screen.getByPlaceholderText(/Enter a detailed description/i);
    const analyzeButton = screen.getByRole('button', { name: /Analyze Threat/i });
    
    fireEvent.change(textarea, { target: { value: 'Test' }});
    fireEvent.click(analyzeButton);

    // Wait for error
    await waitFor(() => {
      expect(screen.getByText(/Failed to analyze threat/i)).toBeInTheDocument();
    });

    // Now mock success and try again
    mockThreatAPI.analyzeThreat.mockResolvedValue({
      predicted_category: 'Malware',
      confidence: 0.8
    });

    fireEvent.change(textarea, { target: { value: 'New test description' }});
    fireEvent.click(analyzeButton);

    // Error should be cleared and result should show
    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/i)).toBeInTheDocument();
    });
    
    expect(screen.queryByText(/Failed to analyze threat/i)).not.toBeInTheDocument();
  });
});