// frontend/tests/Dashboard.test.tsx
import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import Dashboard from '../src/components/Dashboard';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

// Mock stats data
const mockStats = {
  total: 1100,
  by_category: { Malware: 500, Phishing: 300, DDoS: 200, Ransomware: 100 },
  by_severity: { Low: 300, Medium: 400, High: 300, Critical: 100 },
};

// Setup mock server for /api/test and /api/stats
const server = setupServer(
  http.get('http://localhost:8000/api/test', () => {
    return HttpResponse.json({ message: 'API is working!' }, { status: 200 });
  }),
  http.get('http://localhost:8000/api/stats', () => {
    return HttpResponse.json(mockStats, { status: 200 });
  }),
);

// Setup and teardown
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

// Mock fetch globally if needed
global.fetch = jest.fn();

describe('Dashboard Component', () => {
  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  test('shows connection testing then connected and renders stats', async () => {
    render(<Dashboard />);

    // Initially shows "Testing..." indicator
    expect(screen.getByText(/Testing\.\.\./i)).toBeInTheDocument();

    // After /api/test, should show "Connected"
    await waitFor(() => {
      expect(screen.getByText(/Connected/i)).toBeInTheDocument();
    }, { timeout: 5000 });

    // Then stats load: Total Threats card
    await waitFor(() => {
      expect(screen.getByText(/Total Threats/i)).toBeInTheDocument();
      expect(screen.getByText('1,100')).toBeInTheDocument();
    }, { timeout: 5000 });
  });

  test('shows troubleshooting card when connection fails', async () => {
    // Make /api/test fail
    server.use(
      http.get('http://localhost:8000/api/test', () => {
        return HttpResponse.json({ error: 'Server error' }, { status: 500 });
      })
    );

    render(<Dashboard />);

    // Should show Disconnected troubleshooting card
    await waitFor(() => {
      expect(screen.getByText(/Connection Issues/i)).toBeInTheDocument();
    }, { timeout: 5000 });

    // Should show disconnected status
    await waitFor(() => {
      expect(screen.getByText(/Disconnected/i)).toBeInTheDocument();
    });
  });

  test('retry button triggers fetch again on failure', async () => {
    // Make /api/test fail initially
    server.use(
      http.get('http://localhost:8000/api/test', () => {
        return HttpResponse.json({ error: 'Server error' }, { status: 500 });
      })
    );

    render(<Dashboard />);

    // Should show Disconnected troubleshooting card
    await waitFor(() => {
      expect(screen.getByText(/Connection Issues/i)).toBeInTheDocument();
    });

    // Restore /api/test success before clicking retry
    server.use(
      http.get('http://localhost:8000/api/test', () => {
        return HttpResponse.json({ message: 'OK' }, { status: 200 });
      }),
      http.get('http://localhost:8000/api/stats', () => {
        return HttpResponse.json(mockStats, { status: 200 });
      }),
    );

    // Click "Test Connection" to retry
    const testConnectionButton = screen.getByRole('button', { name: /Test Connection/i });
    fireEvent.click(testConnectionButton);

    // After retry, it should load stats
    await waitFor(() => {
      expect(screen.getByText(/Total Threats/i)).toBeInTheDocument();
    }, { timeout: 5000 });
  });

  test('refresh button re-fetches stats', async () => {
    render(<Dashboard />);
    
    // Wait for initial load
    await waitFor(() => {
      expect(screen.getByText('1,100')).toBeInTheDocument();
    }, { timeout: 5000 });

    // Change mockStats for refresh
    const newStats = { ...mockStats, total: 1200 };
    server.use(
      http.get('http://localhost:8000/api/stats', () => {
        return HttpResponse.json(newStats, { status: 200 });
      })
    );

    // Click Refresh button
    const refreshButton = screen.getByRole('button', { name: /Refresh/i });
    fireEvent.click(refreshButton);

    // New value appears
    await waitFor(() => {
      expect(screen.getByText('1,200')).toBeInTheDocument();
    }, { timeout: 5000 });
  });

  test('displays correct number of categories and severity levels', async () => {
    render(<Dashboard />);

    // Wait for stats to load
    await waitFor(() => {
      expect(screen.getByText(/Total Threats/i)).toBeInTheDocument();
    });

    // Check categories count (4 categories in mock data)
    expect(screen.getByText('4')).toBeInTheDocument();

    // Check severity levels count (4 levels in mock data)
    const severityCards = screen.getAllByText('4');
    expect(severityCards).toHaveLength(2); // Both categories and severity show 4
  });

  test('handles network errors gracefully', async () => {
    // Make all requests fail
    server.use(
      http.get('http://localhost:8000/api/test', () => {
        return HttpResponse.error();
      })
    );

    render(<Dashboard />);

    // Should show connection error
    await waitFor(() => {
      expect(screen.getByText(/Connection Issues/i)).toBeInTheDocument();
    });
  });
});