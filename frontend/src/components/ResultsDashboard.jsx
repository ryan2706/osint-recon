import React, { useState } from 'react';

const ResultsDashboard = ({ results, scanId }) => {
    const [viewMode, setViewMode] = useState('summary'); // 'summary' or 'detailed'
    const [activeTab, setActiveTab] = useState('subdomains');

    if (!results) return null;

    const { subdomains, live_hosts, vulnerabilities } = results;

    const severityOrder = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
        'unknown': 0
    };

    const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => {
        const sevA = (a.info?.severity || 'unknown').toLowerCase();
        const sevB = (b.info?.severity || 'unknown').toLowerCase();
        return (severityOrder[sevB] || 0) - (severityOrder[sevA] || 0);
    });

    // Aggregate similar vulnerabilities (same template_id and matched_at)
    const aggregatedVulnerabilities = sortedVulnerabilities.reduce((acc, vuln) => {
        // Use a more relaxed key: template_id + host (ignoring small variations in matched_at if necessary, but visually they look same)
        // Or better, use template_id + matched_at. If they are identical, they condense.
        const key = `${vuln.template_id}|${vuln.matched_at}`;

        if (!acc[key]) {
            acc[key] = {
                ...vuln,
                matchers: [],
                extracted_results_list: []
            };
        }

        // Aggregate matcher names
        if (vuln.matcher_name && !acc[key].matchers.includes(vuln.matcher_name)) {
            acc[key].matchers.push(vuln.matcher_name);
        }

        // Aggregate extracted results
        if (vuln.extracted_results) {
            const extracted = Array.isArray(vuln.extracted_results)
                ? vuln.extracted_results
                : [vuln.extracted_results];
            extracted.forEach(ex => {
                if (!acc[key].extracted_results_list.includes(ex)) {
                    acc[key].extracted_results_list.push(ex);
                }
            });
        }

        return acc;
    }, {});

    const aggregatedList = Object.values(aggregatedVulnerabilities);

    // Group by host
    const groupedVulnerabilities = aggregatedList.reduce((acc, vuln) => {
        const host = vuln.host || 'Unknown Host';
        if (!acc[host]) acc[host] = [];
        acc[host].push(vuln);
        return acc;
    }, {});


    const summaryStats = [
        { label: 'Subdomains', value: subdomains.length, color: 'text-blue-400' },
        { label: 'Live Hosts', value: live_hosts.length, color: 'text-green-400' },
        { label: 'Vulnerabilities', value: vulnerabilities.length, color: 'text-red-400' },
    ];

    return (
        <div className="dashboard-container">
            <div className="stats-grid">
                {summaryStats.map((stat) => (
                    <div key={stat.label} className="stat-card">
                        <h3>{stat.value}</h3>
                        <span>{stat.label}</span>
                    </div>
                ))}
            </div>

            <div className="view-toggle">
                <button
                    className={viewMode === 'summary' ? 'active' : ''}
                    onClick={() => setViewMode('summary')}
                >
                    Overview
                </button>
                <button
                    className={viewMode === 'detailed' ? 'active' : ''}
                    onClick={() => setViewMode('detailed')}
                >
                    Detailed Results
                </button>

                {scanId && (
                    <a
                        href={`/export/${scanId}`}
                        className="export-btn"
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        Export to Excel
                    </a>
                )}
            </div>

            <div className="results-content">
                {viewMode === 'summary' ? (
                    <div className="summary-view">
                        <h4>Live Hosts</h4>
                        <ul>
                            {live_hosts.slice(0, 10).map((host, idx) => (
                                <li key={idx}>{host.url || host.input} ({host.status_code})</li>
                            ))}
                            {live_hosts.length > 10 && <li>...and {live_hosts.length - 10} more</li>}
                        </ul>
                        <h4>Vulnerabilities (Top Critical)</h4>
                        <ul>
                            {sortedVulnerabilities.slice(0, 5).map((vuln, idx) => (
                                <li key={idx} className="vuln-item">
                                    <span className={`severity ${vuln.info?.severity || 'info'}`}>{vuln.info?.severity || 'INFO'}</span>
                                    {vuln.info?.name} at {vuln.matched_at}
                                </li>
                            ))}
                            {sortedVulnerabilities.length === 0 && <li>No vulnerabilities found yet.</li>}
                        </ul>
                    </div>
                ) : (
                    <div className="detailed-view">
                        <div className="detailed-tabs">
                            <button
                                className={activeTab === 'subdomains' ? 'active' : ''}
                                onClick={() => setActiveTab('subdomains')}
                            >
                                Subdomains ({subdomains.length})
                            </button>
                            <button
                                className={activeTab === 'hosts' ? 'active' : ''}
                                onClick={() => setActiveTab('hosts')}
                            >
                                Live Hosts ({live_hosts.length})
                            </button>
                            <button
                                className={activeTab === 'vulns' ? 'active' : ''}
                                onClick={() => setActiveTab('vulns')}
                            >
                                Vulnerabilities ({vulnerabilities.length})
                            </button>
                        </div>

                        <div className="tab-content">
                            {activeTab === 'subdomains' && (
                                <div className="results-grid">
                                    {subdomains.map((sub, idx) => (
                                        <div key={idx} className="result-card simple">
                                            {sub}
                                        </div>
                                    ))}
                                    {subdomains.length === 0 && <p className="empty-state">No subdomains found.</p>}
                                </div>
                            )}

                            {activeTab === 'hosts' && (
                                <div className="hosts-list">
                                    {live_hosts.map((host, idx) => (
                                        <div key={idx} className="result-card host-card">
                                            <div className="host-header">
                                                <a href={host.url} target="_blank" rel="noopener noreferrer" className="host-url">
                                                    {host.url}
                                                </a>
                                                <span className={`status-badge status-${host.status_code}`}>
                                                    {host.status_code}
                                                </span>
                                            </div>
                                            <div className="host-details">
                                                {host.title && <div className="detail-row"><strong>Title:</strong> {host.title}</div>}
                                                {host.webserver && <div className="detail-row"><strong>Server:</strong> {host.webserver}</div>}
                                                {host.tech && <div className="detail-row"><strong>Tech:</strong> {host.tech.join(', ')}</div>}
                                                <div className="detail-row"><strong>IP:</strong> {host.host}</div>
                                            </div>
                                        </div>
                                    ))}
                                    {live_hosts.length === 0 && <p className="empty-state">No live hosts found.</p>}
                                </div>
                            )}

                            {activeTab === 'vulns' && (
                                <div className="vulns-list">
                                    {Object.entries(groupedVulnerabilities).map(([host, vulns]) => (
                                        <div key={host} className="vuln-group">
                                            <h3 className="vuln-group-title sticky-header">
                                                {host} <span className="badge-count">{vulns.length} issues found</span>
                                            </h3>
                                            {vulns.map((vuln, idx) => (
                                                <div key={idx} className="result-card vuln-card">
                                                    <div className="vuln-header">
                                                        <div className="vuln-title-group">
                                                            <span className={`severity ${vuln.info?.severity || 'info'}`}>
                                                                {vuln.info?.severity || 'INFO'}
                                                            </span>
                                                            <span className="vuln-name">{vuln.info?.name || vuln.template_id}</span>
                                                        </div>
                                                    </div>
                                                    <div className="vuln-body">
                                                        <div className="detail-row">
                                                            <strong>Target URL:</strong>
                                                            <a href={vuln.matched_at} target="_blank" rel="noopener noreferrer" className="vuln-link">
                                                                {vuln.matched_at}
                                                            </a>
                                                        </div>

                                                        {vuln.info?.description && <p className="vuln-desc">{vuln.info.description}</p>}

                                                        {/* Aggregated Matchers */}
                                                        {vuln.matchers && vuln.matchers.length > 0 && (
                                                            <div className="vuln-extra-block">
                                                                <strong>Matchers:</strong>
                                                                <div className="matchers-list">
                                                                    {vuln.matchers.map((m, mIdx) => (
                                                                        <span key={mIdx} className="meta-tag">{m}</span>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        )}

                                                        {/* Aggregated Extracted Results */}
                                                        {vuln.extracted_results_list && vuln.extracted_results_list.length > 0 && (
                                                            <div className="vuln-extra-block">
                                                                <strong>Extracted Data:</strong>
                                                                <pre className="code-block">{vuln.extracted_results_list.join('\n')}</pre>
                                                            </div>
                                                        )}

                                                        {/* References */}
                                                        {vuln.info?.reference && vuln.info.reference.length > 0 && (
                                                            <div className="vuln-extra-block">
                                                                <strong>References:</strong>
                                                                <ul className="ref-list">
                                                                    {vuln.info.reference.map((ref, rIdx) => (
                                                                        <li key={rIdx}><a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a></li>
                                                                    ))}
                                                                </ul>
                                                            </div>
                                                        )}

                                                        {/* Classification / CVD */}
                                                        {vuln.info?.classification && (
                                                            <div className="vuln-extra-block">
                                                                <strong>Classification:</strong>
                                                                <div className="classification-tags">
                                                                    {vuln.info.classification.cve_id && <span className="meta-tag cve">{vuln.info.classification.cve_id}</span>}
                                                                    {vuln.info.classification.cwe_id && <span className="meta-tag">{vuln.info.classification.cwe_id}</span>}
                                                                    {vuln.info.classification.cvss_score && <span className="meta-tag">CVSS: {vuln.info.classification.cvss_score}</span>}
                                                                </div>
                                                            </div>
                                                        )}

                                                        <div className="vuln-meta">
                                                            {vuln.info?.tags && <span className="meta-tag">Tags: {vuln.info.tags.join(', ')}</span>}
                                                            {vuln.type && <span className="meta-tag">Type: {vuln.type}</span>}
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    ))}
                                    {vulnerabilities.length === 0 && <p className="empty-state">No vulnerabilities detected.</p>}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ResultsDashboard;
