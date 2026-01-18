// Azure Permission Analyzer - Frontend JavaScript

// Global configuration
const APP_CONFIG = {
    API_BASE_URL: '',
    POLLING_INTERVAL: 2000,
    TOAST_DURATION: 5000
};

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Initialize file upload handling
    initializeFileUpload();

    // Initialize theme handling
    initializeTheme();

    // Auto-refresh results page
    if (window.location.pathname === '/results') {
        initializeResultsPage();
    }
}

// File upload handling
function initializeFileUpload() {
    const fileInput = document.getElementById('user_list_file');
    if (!fileInput) return;

    fileInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (!file) return;

        // Validate file type
        if (!file.name.endsWith('.txt')) {
            showToast('Please upload a .txt file', 'error');
            e.target.value = '';
            return;
        }

        // Validate file size (max 1MB)
        if (file.size > 1024 * 1024) {
            showToast('File too large. Maximum size is 1MB', 'error');
            e.target.value = '';
            return;
        }

        // Preview file content
        const reader = new FileReader();
        reader.onload = function(e) {
            const content = e.target.result;
            const lines = content.split('\n').filter(line => line.trim());

            if (lines.length === 0) {
                showToast('File appears to be empty', 'warning');
                return;
            }

            if (lines.length > 100) {
                showToast(`File contains ${lines.length} users. Large batches may take longer to process.`, 'info');
            }

            // Validate user ID format (basic check)
            const invalidLines = lines.filter(line => {
                const trimmed = line.trim();
                return trimmed && !isValidUserIdFormat(trimmed);
            });

            if (invalidLines.length > 0) {
                showToast(`Warning: ${invalidLines.length} lines don't look like valid user IDs`, 'warning');
            }
        };
        reader.readAsText(file);
    });
}

// Validate user ID format (basic GUID pattern check)
function isValidUserIdFormat(userId) {
    const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return guidPattern.test(userId);
}

// Theme handling
function initializeTheme() {
    // Check for saved theme preference or default to 'light'
    const savedTheme = localStorage.getItem('theme') || 'light';
    setTheme(savedTheme);

    // Add theme toggle if it exists
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);

    // Update theme toggle icon
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        const icon = themeToggle.querySelector('i');
        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }
}

function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}

// Results page initialization
function initializeResultsPage() {
    // Auto-refresh every 30 seconds if there are running analyses
    setInterval(checkForUpdates, 30000);
}

async function checkForUpdates() {
    // This could be enhanced to check for real-time updates
    // For now, we'll just refresh if the user hasn't interacted recently
    if (document.hidden) return; // Don't refresh if tab is not active

    const lastActivity = parseInt(localStorage.getItem('lastActivity') || '0');
    const now = Date.now();

    if (now - lastActivity > 60000) { // If no activity for 1 minute
        // Could add a subtle notification here
        console.log('Checking for updates...');
    }
}

// Track user activity
['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
    document.addEventListener(event, () => {
        localStorage.setItem('lastActivity', Date.now().toString());
    }, { passive: true });
});

// Toast notifications
function showToast(message, type = 'info', duration = APP_CONFIG.TOAST_DURATION) {
    // Remove existing toasts
    const existingToasts = document.querySelectorAll('.toast');
    existingToasts.forEach(toast => {
        const bsToast = bootstrap.Toast.getInstance(toast);
        if (bsToast) bsToast.hide();
    });

    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '1080';
        document.body.appendChild(toastContainer);
    }

    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toastHTML = `
        <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <i class="fas fa-${getToastIcon(type)} text-${getToastColor(type)} me-2"></i>
                <strong class="me-auto">${getToastTitle(type)}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;

    toastContainer.insertAdjacentHTML('beforeend', toastHTML);

    // Initialize and show toast
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, {
        delay: duration
    });

    toast.show();

    // Clean up after toast is hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

function getToastIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-triangle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function getToastColor(type) {
    const colors = {
        'success': 'success',
        'error': 'danger',
        'warning': 'warning',
        'info': 'info'
    };
    return colors[type] || 'info';
}

function getToastTitle(type) {
    const titles = {
        'success': 'Success',
        'error': 'Error',
        'warning': 'Warning',
        'info': 'Information'
    };
    return titles[type] || 'Notification';
}

// Copy to clipboard utility
function copyToClipboard(text, successMessage = 'Copied to clipboard!') {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showToast(successMessage, 'success');
        }).catch(() => {
            fallbackCopyToClipboard(text, successMessage);
        });
    } else {
        fallbackCopyToClipboard(text, successMessage);
    }
}

function fallbackCopyToClipboard(text, successMessage) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        document.execCommand('copy');
        showToast(successMessage, 'success');
    } catch (err) {
        showToast('Failed to copy to clipboard', 'error');
    }

    document.body.removeChild(textArea);
}

// Form validation helpers
function validateForm(formElement) {
    const requiredFields = formElement.querySelectorAll('[required]');
    let isValid = true;
    let firstInvalidField = null;

    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            isValid = false;
            field.classList.add('is-invalid');

            if (!firstInvalidField) {
                firstInvalidField = field;
            }
        } else {
            field.classList.remove('is-invalid');
        }
    });

    // Focus on first invalid field
    if (firstInvalidField) {
        firstInvalidField.focus();
        firstInvalidField.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    return isValid;
}

// Add validation to form inputs
document.addEventListener('input', function(e) {
    if (e.target.hasAttribute('required')) {
        if (e.target.value.trim()) {
            e.target.classList.remove('is-invalid');
            e.target.classList.add('is-valid');
        } else {
            e.target.classList.remove('is-valid');
        }
    }
});

// Loading states
function setLoadingState(element, isLoading, originalText = null) {
    if (isLoading) {
        element.dataset.originalText = element.innerHTML;
        element.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Loading...';
        element.disabled = true;
    } else {
        element.innerHTML = originalText || element.dataset.originalText || element.innerHTML;
        element.disabled = false;
        delete element.dataset.originalText;
    }
}

// Debounce utility
function debounce(func, wait, immediate) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            if (!immediate) func(...args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func(...args);
    };
}

// Search/filter functionality
function initializeSearch(searchInputId, targetSelector, searchFields = ['textContent']) {
    const searchInput = document.getElementById(searchInputId);
    if (!searchInput) return;

    const debouncedSearch = debounce((query) => {
        filterElements(targetSelector, query, searchFields);
    }, 300);

    searchInput.addEventListener('input', (e) => {
        debouncedSearch(e.target.value);
    });
}

function filterElements(selector, query, searchFields) {
    const elements = document.querySelectorAll(selector);
    const searchTerm = query.toLowerCase().trim();

    elements.forEach(element => {
        let shouldShow = false;

        if (!searchTerm) {
            shouldShow = true;
        } else {
            searchFields.forEach(field => {
                if (shouldShow) return;

                let content = '';
                if (field === 'textContent') {
                    content = element.textContent.toLowerCase();
                } else if (element.dataset[field]) {
                    content = element.dataset[field].toLowerCase();
                } else if (element.querySelector(`[data-${field}]`)) {
                    content = element.querySelector(`[data-${field}]`).textContent.toLowerCase();
                }

                if (content.includes(searchTerm)) {
                    shouldShow = true;
                }
            });
        }

        element.style.display = shouldShow ? '' : 'none';
    });
}

// Animation utilities
function fadeIn(element, duration = 300) {
    element.style.opacity = '0';
    element.style.display = 'block';

    const start = performance.now();

    function animate(currentTime) {
        const elapsed = currentTime - start;
        const progress = Math.min(elapsed / duration, 1);

        element.style.opacity = progress;

        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }

    requestAnimationFrame(animate);
}

function fadeOut(element, duration = 300) {
    const start = performance.now();
    const startOpacity = parseFloat(getComputedStyle(element).opacity);

    function animate(currentTime) {
        const elapsed = currentTime - start;
        const progress = Math.min(elapsed / duration, 1);

        element.style.opacity = startOpacity * (1 - progress);

        if (progress < 1) {
            requestAnimationFrame(animate);
        } else {
            element.style.display = 'none';
        }
    }

    requestAnimationFrame(animate);
}

// Export utilities for use in other scripts
window.AzurePermissionAnalyzer = {
    showToast,
    copyToClipboard,
    validateForm,
    setLoadingState,
    debounce,
    initializeSearch,
    filterElements,
    fadeIn,
    fadeOut
};