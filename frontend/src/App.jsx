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

  const [selectedTargets, setSelectedTargets] = useState([]);

  const startDiscovery = async (domain) => {
    setLoading(true);
    setError(null);
    setResults(null);
    setStatus('starting_discovery');

    try {
      const response = await fetch('/scan/discovery', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });

      if (!response.ok) throw new Error('Failed to start discovery');

      const data = await response.json();
      setScanId(data.scan_id);
      setStatus('running_discovery');
    } catch (err) {
      setError(err.message);
      setLoading(false);
      setStatus('error');
    }
  };

  const startNucleiScan = async () => {
    if (!scanId || selectedTargets.length === 0) return;

    setLoading(true);
    setStatus('starting_nuclei');

    try {
      const response = await fetch('/scan/nuclei', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, targets: selectedTargets })
      });

      if (!response.ok) throw new Error('Failed to start Nuclei scan');

      setStatus('running_nuclei');
    } catch (err) {
      setError(err.message);
      setLoading(false);
      setStatus('error');
    }
  };

  useEffect(() => {
    let interval;
    if (scanId && (status === 'running_discovery' || status === 'running_nuclei')) {
      interval = setInterval(async () => {
        try {
          const response = await fetch(`/scan/${scanId}`);
          if (response.ok) {
            const data = await response.json();

            if (data.status === 'discovery_completed') {
              setResults(data.data);
              setStatus('discovery_completed');
              setLoading(false);
              clearInterval(interval);
            } else if (data.status === 'scan_completed') {
              setResults(data.data);
              setStatus('scan_completed');
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
        <ScanForm onScanStart={startDiscovery} isLoading={loading} />

        {error && <div className="error-message">{error}</div>}

        {(status === 'running_discovery' || status === 'running_nuclei') && (
          <div className="loading-status">
            <div className="spinner"></div>
            <p>
              {status === 'running_discovery'
                ? 'Running Discovery (Subfinder & HTTPX)...'
                : 'Running Nuclei Scan on selected targets...'}
            </p>
          </div>
        )}

        {status === 'discovery_completed' && results && results.live_hosts && (
          <div className="discovery-results">
            <h3>Discovery Complete</h3>
            <p>Select targets to scan with Nuclei:</p>

            <div className="target-selection">
              <div className="selection-controls">
                <button onClick={() => setSelectedTargets(results.live_hosts.map(h => h.url))}>Select All</button>
                <button onClick={() => setSelectedTargets([])}>Deselect All</button>
                <span className="selection-count">{selectedTargets.length} targets selected</span>
              </div>

              <ul className="target-list">
                {results.live_hosts.map((host, idx) => (
                  <li key={idx}>
                    <label>
                      <input
                        type="checkbox"
                        checked={selectedTargets.includes(host.url)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedTargets(prev => [...prev, host.url]);
                          } else {
                            setSelectedTargets(prev => prev.filter(t => t !== host.url));
                          }
                        }}
                      />
                      {host.url} <span className="status-code">({host.status_code})</span> - {host.title}
                    </label>
                  </li>
                ))}
              </ul>

              <button
                className="start-nuclei-btn"
                onClick={startNucleiScan}
                disabled={selectedTargets.length === 0}
              >
                Run Nuclei Scan
              </button>
            </div>
          </div>
        )}

        {status === 'scan_completed' && results && <ResultsDashboard results={results} scanId={scanId} />}
      </main>
    </div>
  )
}

export default App
