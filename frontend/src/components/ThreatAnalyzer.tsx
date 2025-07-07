import React, { useState } from 'react';
import { Send, Brain, AlertCircle, CheckCircle, Loader, Info } from 'lucide-react';
import { threatAPI } from '../api';

interface AnalysisResult {
  predicted_category: string;
  confidence: number;
}

const ThreatAnalyzer: React.FC = () => {
  const [description, setDescription] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!description.trim()) {
      setError('Please enter a threat description');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setResult(null);
      
      const data = await threatAPI.analyzeThreat(description);
      setResult(data);
    } catch (err) {
      setError('Failed to analyze threat. This feature requires ML model implementation in the backend.');
      console.error('Error analyzing threat:', err);
    } finally {
      setLoading(false);
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-green-400';
    if (confidence >= 0.6) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getConfidenceLevel = (confidence: number) => {
    if (confidence >= 0.8) return 'High';
    if (confidence >= 0.6) return 'Medium';
    return 'Low';
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center">
        <Brain className="h-12 w-12 text-blue-400 mx-auto mb-4" />
        <h2 className="text-3xl font-bold text-white mb-2">Threat Analyzer</h2>
        <p className="text-gray-400">
          Use machine learning to analyze and categorize threat descriptions
        </p>
      </div>

      {/* Info Banner */}
      <div className="bg-blue-900/20 border border-blue-500 rounded-lg p-4">
        <div className="flex items-start">
          <Info className="h-5 w-5 text-blue-400 mt-0.5 mr-3 flex-shrink-0" />
          <div>
            <h4 className="text-sm font-medium text-blue-300 mb-1">ML Model Integration</h4>
            <p className="text-sm text-gray-300">
              This analyzer currently shows demo predictions. To enable real ML analysis, implement the 
              <code className="mx-1 px-1 bg-gray-800 rounded text-blue-300">/api/analyze</code> endpoint 
              in your backend using the <code className="mx-1 px-1 bg-gray-800 rounded text-blue-300">ml_model.py</code> file.
            </p>
          </div>
        </div>
      </div>

      {/* Analysis Form */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="description" className="block text-sm font-medium text-gray-300 mb-2">
              Threat Description
            </label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Enter a detailed description of the threat to analyze..."
              rows={6}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">
              {description.length}/1000 characters
            </div>
            <button
              type="submit"
              disabled={loading || !description.trim()}
              className="flex items-center px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-md transition-colors"
            >
              {loading ? (
                <>
                  <Loader className="h-4 w-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Send className="h-4 w-4 mr-2" />
                  Analyze Threat
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 text-center">
          <AlertCircle className="h-8 w-8 text-red-400 mx-auto mb-2" />
          <p className="text-red-300">{error}</p>
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div className="flex items-center mb-4">
            <CheckCircle className="h-6 w-6 text-green-400 mr-2" />
            <h3 className="text-lg font-semibold text-white">Analysis Complete</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Predicted Category */}
            <div className="bg-gray-900 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Predicted Category</h4>
              <div className="flex items-center">
                <span className="text-2xl font-bold text-white">{result.predicted_category}</span>
              </div>
            </div>

            {/* Confidence Score */}
            <div className="bg-gray-900 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Confidence Score</h4>
              <div className="flex items-center space-x-4">
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-lg font-bold ${getConfidenceColor(result.confidence)}`}>
                      {(result.confidence * 100).toFixed(1)}%
                    </span>
                    <span className={`text-sm ${getConfidenceColor(result.confidence)}`}>
                      {getConfidenceLevel(result.confidence)}
                    </span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full transition-all duration-300 ${
                        result.confidence >= 0.8
                          ? 'bg-green-400'
                          : result.confidence >= 0.6
                          ? 'bg-yellow-400'
                          : 'bg-red-400'
                      }`}
                      style={{ width: `${result.confidence * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Interpretation */}
          <div className="mt-6 p-4 bg-blue-900/20 border border-blue-500 rounded-lg">
            <h4 className="text-sm font-medium text-blue-300 mb-2">Interpretation</h4>
            <p className="text-gray-300 text-sm">
              {result.confidence >= 0.8
                ? 'The model is highly confident in this prediction. This threat likely belongs to the predicted category.'
                : result.confidence >= 0.6
                ? 'The model has moderate confidence in this prediction. Consider additional context or manual review.'
                : 'The model has low confidence in this prediction. Manual review is recommended to verify the categorization.'}
            </p>
          </div>
        </div>
      )}

      {/* Example Descriptions */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Example Descriptions</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Malware</h4>
            <p className="text-sm text-gray-400 italic">
              "Suspicious executable file detected with capability to encrypt files and demand ransom payment..."
            </p>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Phishing</h4>
            <p className="text-sm text-gray-400 italic">
              "Fraudulent email campaign impersonating financial institution requesting login credentials..."
            </p>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Network Attack</h4>
            <p className="text-sm text-gray-400 italic">
              "Distributed denial of service attack targeting web servers with overwhelming traffic..."
            </p>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Data Breach</h4>
            <p className="text-sm text-gray-400 italic">
              "Unauthorized access to customer database containing personal information and payment details..."
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatAnalyzer;