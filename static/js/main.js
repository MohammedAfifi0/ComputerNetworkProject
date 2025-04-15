document.addEventListener('DOMContentLoaded', function() {
    // Check for active scans and update their status
    const activeScans = document.querySelectorAll('.active-scan');
    if (activeScans.length > 0) {
        updateActiveScans();
        // Set an interval to update active scans every 5 seconds
        setInterval(updateActiveScans, 5000);
    }

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Target input validation
    const targetInput = document.getElementById('target');
    if (targetInput) {
        targetInput.addEventListener('input', validateTarget);
    }

    // Form validation
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            if (!validateTarget()) {
                event.preventDefault();
                alert('Please enter a valid IP address or range.');
            }
        });
    }

    // Confirmation for deleting reports
    const deleteButtons = document.querySelectorAll('.delete-report');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            if (!confirm('Are you sure you want to delete this report?')) {
                event.preventDefault();
            }
        });
    });

    // Confirmation for cancelling scans
    const cancelButtons = document.querySelectorAll('.cancel-scan');
    cancelButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            if (!confirm('Are you sure you want to cancel this scan?')) {
                event.preventDefault();
            }
        });
    });
});

function validateTarget() {
    const targetInput = document.getElementById('target');
    const targetValue = targetInput.value.trim();
    const targetFeedback = document.getElementById('target-feedback');
    
    // Simple validation for IP addresses, CIDR ranges, and hostnames
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[1-2][0-9]|[0-9]))?$/;
    const hostnameRegex = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/;
    
    if (targetValue === '') {
        targetFeedback.textContent = 'Please enter a target IP or hostname.';
        targetFeedback.classList.remove('d-none');
        return false;
    } else if (!ipRegex.test(targetValue) && !hostnameRegex.test(targetValue)) {
        targetFeedback.textContent = 'Please enter a valid IP address, CIDR range, or hostname.';
        targetFeedback.classList.remove('d-none');
        return false;
    } else {
        targetFeedback.textContent = '';
        targetFeedback.classList.add('d-none');
        return true;
    }
}

function updateActiveScans() {
    const activeScans = document.querySelectorAll('.active-scan');
    
    activeScans.forEach(scan => {
        const scanId = scan.getAttribute('data-scan-id');
        const statusElement = scan.querySelector('.scan-status');
        
        fetch(`/scan_status/${scanId}`)
            .then(response => response.json())
            .then(data => {
                statusElement.textContent = data.status;
                
                // If the scan is no longer active, refresh the page
                if (data.status !== 'queued' && data.status !== 'running') {
                    setTimeout(() => {
                        window.location.reload();
                    }, 2000);
                }
            })
            .catch(error => {
                console.error('Error fetching scan status:', error);
            });
    });
}

// Toggle vulnerability details
function toggleVulnerabilityDetails(element) {
    const detailsElement = document.getElementById(element.getAttribute('data-target'));
    if (detailsElement) {
        if (detailsElement.classList.contains('d-none')) {
            detailsElement.classList.remove('d-none');
            element.textContent = 'Hide Details';
        } else {
            detailsElement.classList.add('d-none');
            element.textContent = 'Show Details';
        }
    }
}

// Format date function
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    return date.toLocaleString();
}
