const CHAR_LIMIT = 10000; // Approximately 3000-4000 tokens

function updateCharCount(textarea) {
    const charCount = textarea.value.length;
    const counter = document.getElementById('charCount');
    const counterDiv = document.querySelector('.char-counter');

    counter.textContent = charCount;

    // Visual feedback when approaching/reaching limit
    if (charCount >= CHAR_LIMIT) {
        textarea.value = textarea.value.slice(0, CHAR_LIMIT);
        counterDiv.classList.add('limit-reached');
    } else {
        counterDiv.classList.remove('limit-reached');
    }
}


function updateCirclePercentage(circleId, percentage) {
    const circle = document.getElementById(circleId);
    const scoreText = document.getElementById(circleId.replace('Circle', 'Score'));
    if (!circle || !scoreText) return;

    const radius = 16;
    const circumference = radius * 2 * Math.PI;

    // Ensure percentage is between 0 and 100
    percentage = Math.max(0, Math.min(100, percentage));

    const offset = circumference - (percentage / 100 * circumference);
    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = offset;

    // Update the percentage text
    scoreText.textContent = `${Math.round(percentage)}%`;

    // Update circle color based on score
    if (percentage >= 80) {
        circle.style.stroke = '#4caf50';  // Green
    } else if (percentage >= 60) {
        circle.style.stroke = '#ff9800';  // Orange
    } else {
        circle.style.stroke = '#f44336';  // Red
    }
}

// Store analysis results
function storeResults(data) {
    sessionStorage.setItem('analysisResults', JSON.stringify(data));
}

// Function to get risk level based on score
function getRiskLevel(score) {
    if (score >= 80) return 'Low';
    if (score >= 60) return 'Medium';
    return 'High';
}

// Function to count critical issues
function countCriticalIssues(data) {
    let criticalCount = 0;

    // Check static analysis
    if (data.static_analysis?.static_analyzer?.issues?.security) {
        criticalCount += data.static_analysis.static_analyzer.issues.security.filter(
            issue => issue.severity === 'HIGH'
        ).length;
    }

    // Check dependency analysis
    if (data.dependency_analysis?.vulnerable_packages) {
        data.dependency_analysis.vulnerable_packages.forEach(pkg => {
            if (pkg.vulnerabilities) {
                criticalCount += pkg.vulnerabilities.filter(
                    vuln => vuln.severity === 'CRITICAL'
                ).length;
            }
        });
    }

    // Check AI analysis
    if (data.ai_analysis?.data?.findings) {
        criticalCount += data.ai_analysis.data.findings.filter(
            finding => finding.severity === 'high'
        ).length;
    }

    return criticalCount;
}

// Function to display analysis results
function displayResults(data) {
    try {
        // Store results for persistence
        storeResults(data);

        // Check if we received an error response
        if (data.error) {
            alert(data.error);
            return;
        }

        // Update overall security score if it exists
        if (data.overall_security_score !== undefined) {
            updateCirclePercentage('overallSecurityCircle', data.overall_security_score);
            document.getElementById('riskLevel').textContent = getRiskLevel(data.overall_security_score);
        }

        // Initialize counters
        let totalIssues = 0;
        let criticalIssues = 0;

        // Update static analysis if data exists
        if (data.static_analysis?.static_analyzer) {
            const staticIssues = data.static_analysis.static_analyzer.summary?.total_issues || 0;
            totalIssues += staticIssues;
            const staticScore = Math.max(0, 100 - (staticIssues * 3)); // Changed multiplier to 3
            updateCirclePercentage('staticAnalysisCircle', staticScore);
            document.getElementById('staticIssues').textContent = staticIssues;
        }

        // Update dependency analysis if data exists
        if (data.dependency_analysis) {
            const depIssues = data.dependency_analysis.total_vulnerabilities_found || 0;
            totalIssues += depIssues;
            const depScore = Math.max(0, 100 - (depIssues * 5)); // Changed multiplier to 5
            updateCirclePercentage('dependencyAnalysisCircle', depScore);
            document.getElementById('dependencyIssues').textContent = depIssues;
        }

        // Update AI analysis if data exists
        if (data.ai_analysis?.data) {
            const aiIssues = data.ai_analysis.data.findings?.length || 0;
            totalIssues += aiIssues;
            // Changed to use risk_score with multiplier of 8
            const aiScore = Math.max(0, 100 - ((data.ai_analysis.data.risk_score || 0) * 8));
            updateCirclePercentage('aiAnalysisCircle', aiScore);
            document.getElementById('aiIssues').textContent = aiIssues;
        }

        // Update total issues count
        document.getElementById('totalIssues').textContent = totalIssues;

        // Calculate and update critical issues
        criticalIssues = countCriticalIssues(data);
        document.getElementById('criticalIssues').textContent = criticalIssues;

    } catch (error) {
        console.error('Error processing results:', error);
        alert('Error processing analysis results. Please try again.');
    }
}

// Function to analyze code
async function analyzeCode() {
    const codeInput = document.getElementById('codeInput');
    const code = codeInput.value;
    const progressBar = document.getElementById('progressBar');
    const analyzeBtn = document.getElementById('analyzeBtn');

    if (!code.trim()) {
        alert('Please enter some code to analyze.');
        return;
    }

    if (code.length > CHAR_LIMIT) {
        alert(`Code exceeds maximum length of ${CHAR_LIMIT} characters. Please reduce the code size.`);
        return;
    }

    progressBar?.classList.remove('hidden');
    if (analyzeBtn) analyzeBtn.disabled = true;

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ code: code }),
        });

        if (!response.ok) {
            throw new Error('Analysis failed');
        }

        const data = await response.json();
        displayResults(data);

    } catch (error) {
        console.error('Error:', error);
        alert(error.message || 'Error analyzing code. Please try again.');
    } finally {
        progressBar?.classList.add('hidden');
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
}

// Function to navigate to analysis details
function navigateToAnalysis(type) {
    const storedResults = sessionStorage.getItem('analysisResults');
    if (!storedResults) {
        alert('Please run a code analysis first.');
        return;
    }
    window.location.href = `/${type}`;
}

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the main dashboard page
    if (window.location.pathname === '/') {
        // Check if this is a page refresh/reload
        if (performance.navigation.type === 1) {
            // Clear session storage
            sessionStorage.clear();

            // Reset all UI elements
            const codeInput = document.getElementById('codeInput');
            if (codeInput) codeInput.value = '';

            // Reset all scores to 0
            updateCirclePercentage('overallSecurityCircle', 0);
            updateCirclePercentage('staticAnalysisCircle', 0);
            updateCirclePercentage('dependencyAnalysisCircle', 0);
            updateCirclePercentage('aiAnalysisCircle', 0);

            // Reset all counters
            document.getElementById('totalIssues').textContent = '0';
            document.getElementById('criticalIssues').textContent = '0';
            document.getElementById('staticIssues').textContent = '0';
            document.getElementById('dependencyIssues').textContent = '0';
            document.getElementById('aiIssues').textContent = '0';
            document.getElementById('riskLevel').textContent = 'Low';
        } else {
            // Not a refresh - load any existing results
            const storedResults = sessionStorage.getItem('analysisResults');
            if (storedResults) {
                try {
                    const data = JSON.parse(storedResults);
                    displayResults(data);
                } catch (error) {
                    console.error('Error loading stored results:', error);
                }
            }
        }
    }
});

// Dark mode toggle
function toggleDarkMode() {
    const body = document.body;
    const icon = document.querySelector('.theme-icon');
    body.classList.toggle('dark-mode');
    icon.textContent = body.classList.contains('dark-mode') ? '☀️' : '🌙';
    localStorage.setItem('darkMode', body.classList.contains('dark-mode'));
}

document.addEventListener('DOMContentLoaded', function () {
    const prefersDark = localStorage.getItem('darkMode') === 'true';
    const icon = document.querySelector('.theme-icon');

    if (prefersDark) {
        document.body.classList.add('dark-mode');
        icon.textContent = '☀️';
    } else {
        document.body.classList.remove('dark-mode');
        icon.textContent = '🌙';
    }
});