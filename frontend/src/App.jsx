import { useState } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = 'http://127.0.0.1:8000/analyze';

function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setError(null);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(API_URL, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setResult(response.data);
    } catch (err) {
      const message = err.response?.data?.detail || 'Something went wrong analyzing the file.';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <h1>IAM Attack Path Grapher</h1>
      <p className="subtitle">
        Upload an AWS IAM export to find privilege escalation paths.
      </p>

      <div className="upload-section">
        <input type="file" accept=".json" onChange={handleFileChange} />
        <button onClick={handleAnalyze} disabled={!file || loading}>
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="results">
          <h2>Summary</h2>
          <p>
            {result.summary.principal_count} principals,{' '}
            {result.summary.relationship_count} relationships,{' '}
            {result.summary.finding_count} finding(s)
          </p>

          <h2>Findings</h2>
          {result.findings.length === 0 ? (
            <p>No privilege escalation paths detected.</p>
          ) : (
            <ul className="findings-list">
              {result.findings.map((f, i) => (
                <li key={i} className={`finding severity-${f.severity}`}>
                  <strong>[{f.severity.toUpperCase()}]</strong> {f.principal_name} —{' '}
                  {f.technique_name}
                  <p>{f.description}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
