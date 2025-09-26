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
            <div id="notification-banner" class="notification is-hidden"></div>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Asset</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${findings.slice(0, 10).map(finding => `
                        <tr>
                            <td>${finding.title}</td>
                            <td class="severity-${finding.severity.toLowerCase()}">${finding.severity}</td>
                            <td><code>${finding.asset_id}</code></td>
                            <td>${finding.status}</td>
                            <td>
                                <button class="action-button generate-rules-btn" data-finding-id="${finding.id}">Generate Rules</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        dashboardContent.innerHTML = dashboardHTML;
    };

    const handleGenerateRulesClick = async (event) => {
        const findingId = event.target.dataset.findingId;
        if (!findingId) return;

        showNotification(`Generating rules for finding: ${findingId}...`, 'info');

        try {
            const response = await fetch('/defense/generate-rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ finding_id: findingId }),
            });

            if (!response.ok) {
                throw new Error('Failed to start rule generation.');
            }

            const result = await response.json();
            showNotification(`Successfully started rule generation task: ${result.task_id}`, 'success');

        } catch (error) {
            showNotification(`Error: ${error.message}`, 'error');
            console.error(error);
        }
    };

    const showNotification = (message, type) => {
        const banner = document.getElementById('notification-banner');
        banner.textContent = message;
        banner.className = `notification notification-${type}`;

        setTimeout(() => {
            banner.className = 'notification is-hidden';
        }, 5000);
    };

    dashboardContent.addEventListener('click', (event) => {
        if (event.target.classList.contains('generate-rules-btn')) {
            handleGenerateRulesClick(event);
        }
    });

    fetchData();
});
