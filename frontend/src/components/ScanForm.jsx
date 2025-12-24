import React, { useState } from 'react';

const ScanForm = ({ onScanStart, isLoading }) => {
    const [domain, setDomain] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (domain && !isLoading) {
            onScanStart(domain);
        }
    };

    return (
        <div className="scan-form-container">
            <form onSubmit={handleSubmit} className="scan-form">
                <input
                    type="text"
                    className="domain-input"
                    placeholder="Enter domain (e.g., example.com)"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    disabled={isLoading}
                />
                <button type="submit" className="scan-button" disabled={isLoading || !domain}>
                    {isLoading ? 'Scanning...' : 'Start Recon'}
                </button>
            </form>
        </div>
    );
};

export default ScanForm;
