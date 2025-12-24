import { useState, useEffect } from 'react'
import ScanForm from './components/ScanForm'
import ResultsDashboard from './components/ResultsDashboard'
import './index.css'

function App() {
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('idle');

  const startScan = async (domain) => {
    setLoading(true);
    setError(null);
    setResults(null);
    setStatus('starting');

    try {
      const response = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });

      if (!response.ok) throw new Error('Failed to start scan');

      const data = await response.json();
      setScanId(data.scan_id);
      setStatus('running');
    } catch (err) {
      setError(err.message);
      setLoading(false);
      setStatus('error');
    }
  };

  useEffect(() => {
    let interval;
    if (scanId && status === 'running') {
      interval = setInterval(async () => {
        try {
          const response = await fetch(`/scan/${scanId}`);
          if (response.ok) {
            const data = await response.json();
            if (data.status === 'completed') {
              setResults(data.data);
              setStatus('completed');
              setLoading(false);
              clearInterval(interval);
            } else if (data.status === 'failed') {
              setError(data.error);
              setStatus('failed');
              setLoading(false);
              clearInterval(interval);
            }
          }
        } catch (err) {
          console.error("Polling error", err);
        }
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [scanId, status]);

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>OSINT Recon</h1>
        <p className="subtitle">Advanced Domain Reconnaissance</p>
      </header>

      <main>
        <ScanForm onScanStart={startScan} isLoading={loading} />

        {error && <div className="error-message">{error}</div>}

        {status === 'running' && (
          <div className="loading-status">
            <div className="spinner"></div>
            <p>Scanning in progress... This may take a few minutes.</p>
          </div>
        )}

        {results && <ResultsDashboard results={results} scanId={scanId} />}
      </main>
    </div>
  )
}

export default App
