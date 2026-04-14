$(document).on('click', '.nav-link-c', function (e) {
    e.preventDefault();
    const targetView = $(this).data('view');
    $('.nav-link-c').removeClass('active');
    $(this).addClass('active');
    $('.view-section').removeClass('active');
    $('#' + targetView).addClass('active');
    if (targetView === 'dashboard-view') updateDashboardCharts();
});

$('#btn-scan').on('click', function () {
    const url = $('#url-input').val();
    if (!url) return;
    $('#loading-matrix').css('display', 'flex');

    // Progress and Terminal Simulation
    let progress = 0;
    $('#cyber-progress-bar').css('width', '0%');
    $('#log-list').html('<div>> Establishing secure connection to target...</div>');
    $('#loading-header').html('Initializing Override Protocols... <span id="loading-pct">0%</span>');
    
    const steps = [
        "Resolving DNS Nodes and IP Mapping...",
        "Extracting TLS/SSL Certificates...",
        "Analyzing DOM Structure and iFrames...",
        "Executing Deep Convolutional Neural Net...",
        "Cross-referencing Global Threat Intelligence...",
        "Voting Ensemble (RF+XGB+LGBM) Consensus...",
        "Finalizing Threat Matrix Prediction..."
    ];
    let stepCount = 0;
    
    const timer = setInterval(() => {
        // Increment progress slightly over time
        progress += Math.floor(Math.random() * 5) + 2;
        if (progress > 95) progress = 95;
        $('#cyber-progress-bar').css('width', progress + '%');
        $('#loading-pct').text(progress + '%');
        
        // Randomly add a new log step if there are steps left
        if (Math.random() > 0.6 && stepCount < steps.length) {
            $('#log-list').append(`<div>> ${steps[stepCount]}</div>`);
            stepCount++;
        }
    }, 250);

    $.ajax({
        url: '/scan',
        type: 'POST',
        data: { url: url },
        success: function (data) {
            clearInterval(timer);
            $('#loading-matrix').hide();
            launchMatrixResult(data);
        },
        error: function () {
            clearInterval(timer);
            $('#loading-matrix').hide();
            alert("Interruption in signal.");
        }
    });
});

function launchMatrixResult(data) {
    $('#res-url').text(data.url);
    $('#res-confidence').text(data.confidence + ' CONFIDENCE');
    $('#res-badge').text(data.prediction.toUpperCase());
    let badgeClass = 'status-safe';
    if (data.prediction === 'Phishing') {
        badgeClass = 'status-phish';
    } else if (data.prediction === 'Suspicious') {
        badgeClass = 'status-phish';
    }
    $('#res-badge').removeClass('status-safe status-phish').addClass(badgeClass);
    $('#res-risk').text(data.risk_level.toUpperCase() + '_RISK');
    $('#res-ip').text(data.ip_address);
    $('#res-host').text(data.host_info);
    $('#res-recommendation').text(data.recommendation);
    $('#res-report-link').attr('href', `/report/${data.id}`);
    
    // Prepend to history table
    const newRow = `
        <tr>
            <td class="text-muted small">Just Now</td>
            <td><code class="text-white" style="word-break: break-all;">${data.url}</code></td>
            <td class="text-muted small">${data.ip_address}</td>
            <td class="text-center"><span class="badge-status ${badgeClass}">${data.prediction}</span></td>
            <td class="text-center fw-bold">${parseFloat(data.confidence).toFixed(1)}%</td>
            <td class="text-end"><a href="/report/${data.id}" class="text-white"><i class="fas fa-download"></i></a></td>
        </tr>
    `;
    $('#history-body').prepend(newRow);
    
    // Refresh dashboard stats
    updateDashboardCharts();
    
    $('#scan-results').slideDown();
    renderResultsChart(data);
}

let resultsChart = null;
function renderResultsChart(data) {
    const ctx = document.getElementById('resultsFeatureChart').getContext('2d');
    if (resultsChart) resultsChart.destroy();
    
    // Mocking feature breakdown for the chart
    const labels = ['Domain Entropy', 'URL Length', 'SSL Trust', 'Content Risk', 'Brand Impersonation'];
    const scores = data.prediction === 'Legitimate' ? [10, 15, 5, 12, 8] : [85, 92, 78, 88, 95];

    resultsChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Risk Vector Analysis',
                data: scores,
                fill: true,
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                borderColor: '#ffffff',
                pointBackgroundColor: '#ffffff',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                r: {
                    angleLines: { color: 'rgba(255, 255, 255, 0.05)' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    pointLabels: { color: '#888', font: { size: 10 } },
                    ticks: { display: false, max: 100 }
                }
            }
        }
    });
}

let threatChart = null;
function updateDashboardCharts() {
    $.get('/api/stats', function (stats) {
        $('#stat-total').text(stats.total);
        $('#stat-phishing').text(stats.phishing);
        $('#stat-suspicious').text(stats.suspicious);
        $('#stat-legitimate').text(stats.legitimate);
        const ctx = document.getElementById('threatChart').getContext('2d');
        if (threatChart) threatChart.destroy();
        threatChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Phishing', 'Suspicious', 'Legitimate'],
                datasets: [{
                    data: [stats.phishing, stats.suspicious, stats.legitimate],
                    backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                    borderColor: '#0a0a0a',
                    borderWidth: 8
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                cutout: '82%', 
                plugins: { 
                    legend: { 
                        position: 'right', 
                        labels: { 
                            color: '#888', 
                            font: { size: 12, weight: '600' } 
                        } 
                    } 
                } 
            }
        });
    });
}

$(document).ready(function () { 
    updateDashboardCharts(); 
});

$('#btn-clear-history, #btn-reset-dashboard, #sidebar-clear-history').on('click', function(e) {
    e.preventDefault();
    if (!confirm('Are you sure you want to delete ALL scan history? This cannot be undone.')) return;
    
    $.ajax({
        url: '/api/history/clear',
        type: 'POST',
        success: function(data) {
            // Refresh the UI
            $('#history-body').empty().append('<tr><td colspan="5" class="text-center text-muted py-5 italicize">History is currently empty.</td></tr>');
            updateDashboardCharts();
            alert(data.message);
        },
        error: function(xhr) {
            alert("Error clearing history: " + (xhr.responseJSON ? xhr.responseJSON.error : "Unknown error"));
        }
    });
});
