document.addEventListener('DOMContentLoaded', () => {
    const dashboardContent = document.getElementById('dashboard-content');

    const fetchData = async () => {
        try {
            const [findingsResponse, jobsResponse] = await Promise.all([
                fetch('/findings?limit=1000'), // Fetch a large number of findings for stats
                fetch('/jobs?limit=10') // Fetch the 10 most recent jobs
            ]);

            if (!findingsResponse.ok || !jobsResponse.ok) {
                throw new Error('Failed to fetch data');
            }

            const findingsData = await findingsResponse.json();
            const jobsData = await jobsResponse.json();

            renderDashboard(findingsData.findings, jobsData.jobs);

        } catch (error) {
            dashboardContent.innerHTML = `<div class="error">Failed to load dashboard: ${error.message}</div>`;
            console.error(error);
        }
    };

    const renderDashboard = (findings, jobs) => {
        const summary = {
            totalFindings: findings.length,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0
        };

        findings.forEach(finding => {
            const severity = finding.severity.toLowerCase();
            if (summary.hasOwnProperty(severity)) {
                summary[severity]++;
            }
        });

        const dashboardHTML = `
            <div class="dashboard-grid">
                <div class="widget">
                    <h2>Total Findings</h2>
                    <div class="value">${summary.totalFindings}</div>
                </div>
                <div class="widget">
                    <h2>Critical</h2>
                    <div class="value severity-critical">${summary.critical}</div>
                </div>
                <div class="widget">
                    <h2>High</h2>
                    <div class="value severity-high">${summary.high}</div>
                </div>
                <div class="widget">
                    <h2>Medium</h2>
                    <div class="value severity-medium">${summary.medium}</div>
                </div>
            </div>

            <h2>Recent Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Asset</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${findings.slice(0, 10).map(finding => `
                        <tr>
                            <td>${finding.title}</td>
                            <td class="severity-${finding.severity.toLowerCase()}">${finding.severity}</td>
                            <td><code>${finding.asset_id}</code></td>
                            <td>${finding.status}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        dashboardContent.innerHTML = dashboardHTML;
    };

    fetchData();
});
