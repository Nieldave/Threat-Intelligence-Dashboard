import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import ThreatList from './components/ThreatList';
import ThreatAnalyzer from './components/ThreatAnalyzer';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/threats" element={<ThreatList />} />
          <Route path="/analyzer" element={<ThreatAnalyzer />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;