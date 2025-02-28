// app.js - TiffinTreats Frontend JavaScript

// ================================================
// GLOBAL VARIABLES AND INITIALIZATION
// ================================================

let currentUser = null;
let userRole = null;
let apiKey = null;
const API_BASE_URL = 'https://tiffintreats-20mb.onrender.com';
let activeNotifications = [];

// DOM Ready Event
document.addEventListener('DOMContentLoaded', () => {
    // Check for saved auth
    checkAuthentication();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize dark mode based on preference
    initializeTheme();
});

// ================================================
// API AND AUTHENTICATION FUNCTIONS
// ================================================

async function apiRequest(endpoint, options = {}) {
    // Ensure headers exist
    if (!options.headers) {
        options.headers = {};
    }
    
    // Add the API key if available
    if (apiKey) {
        options.headers['X-API-Key'] = apiKey;
        console.log(`Making ${options.method || 'GET'} request to ${endpoint} with API key: ${apiKey ? "Present" : "Missing"}`);
    }
    
    // Add Content-Type header for POST/PUT/PATCH requests with JSON body
    if (['POST', 'PUT', 'PATCH'].includes(options.method) && options.body) {
        options.headers['Content-Type'] = 'application/json';
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        
        let responseData;
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            responseData = await response.json();
        } else {
            const text = await response.text();
            try {
                // Try to parse as JSON anyway
                responseData = JSON.parse(text);
            } catch (e) {
                // If it's not JSON, just use the text
                responseData = text;
            }
        }
        
        if (!response.ok) {
            console.error(`Error from ${endpoint}:`, responseData);
            
            let errorMessage = 'Request failed';
            
            if (typeof responseData === 'object') {
                if (responseData.detail) {
                    if (Array.isArray(responseData.detail)) {
                        // Handle Pydantic validation errors
                        errorMessage = responseData.detail[0]?.msg || 'Validation error';
                    } else {
                        errorMessage = responseData.detail;
                    }
                } else if (responseData.message) {
                    errorMessage = responseData.message;
                }
            } else if (typeof responseData === 'string') {
                errorMessage = responseData;
            }
            
            throw new Error(errorMessage);
        }
        
        return responseData;
    } catch (error) {
        console.error(`API request to ${endpoint} failed:`, error);
        throw error;
    }
}

function checkAuthentication() {
    const savedAuth = localStorage.getItem('tiffinTreatsAuth');
    
    if (savedAuth) {
        try {
            const auth = JSON.parse(savedAuth);
            apiKey = auth.apiKey;
            userRole = auth.role;
            
            // Make a direct health check to verify API key
            fetch(`${API_BASE_URL}/health`, {
                headers: { 'X-API-Key': apiKey }
            })
            .then(response => {
                if (response.ok) {
                    console.log("API key verified successfully");
                    showApp();
                    loadDashboard();
                } else {
                    console.error("API key verification failed");
                    localStorage.removeItem('tiffinTreatsAuth');
                    showLogin();
                }
            })
            .catch(error => {
                console.error("API key verification error:", error);
                showLogin();
            });
        } catch (error) {
            console.error("Error parsing saved auth:", error);
            showLogin();
        }
    } else {
        console.log("No saved authentication found");
        showLogin();
    }
}

async function login(userId, password) {
    try {
        console.log(`Attempting login for user: ${userId}`);
        
        const response = await fetch(`${API_BASE_URL}/auth/login?user_id=${encodeURIComponent(userId)}&password=${encodeURIComponent(password)}`);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Login failed');
        }
        
        const data = await response.json();
        console.log("Login response:", data);
        
        if (data.status === 'success') {
            apiKey = data.api_key;
            userRole = data.role;
            
            // Save auth data
            localStorage.setItem('tiffinTreatsAuth', JSON.stringify({
                apiKey: apiKey,
                role: userRole
            }));
            
            // For admin, we don't need to fetch profile
            if (userRole === 'admin') {
                currentUser = {
                    name: "Administrator",
                    user_id: "admin",
                    email: "admin@tiffintreats.com",
                    address: "TiffinTreats HQ"
                };
                updateUserInfo();
            } else {
                // Fetch user profile
                await fetchUserProfile();
            }
            
            // Load notifications
            await loadNotifications();
            
            showApp();
            loadDashboard();
            
            return true;
        } else {
            throw new Error('Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showNotification(error.message, 'error');
        return false;
    }
}

function logout() {
    console.log("Logging out user");
    localStorage.removeItem('tiffinTreatsAuth');
    apiKey = null;
    userRole = null;
    currentUser = null;
    showLogin();
}

// ================================================
// UI STATE FUNCTIONS
// ================================================

function showLogin() {
    document.getElementById('auth-container').classList.remove('hidden');
    document.getElementById('app-container').classList.add('hidden');
}

function showApp() {
    document.getElementById('auth-container').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    
    // Show/hide admin section based on role
    const adminSection = document.querySelector('.admin-section');
    if (userRole === 'admin') {
        adminSection.classList.remove('hidden');
    } else {
        adminSection.classList.add('hidden');
    }
}

function navigateTo(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    const page = document.getElementById(`${pageId}-page`);
    if (page) {
        page.classList.add('active');
    }
    
    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    const activeLink = document.querySelector(`.nav-link[data-page="${pageId}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }
    
    // Load page content
    switch (pageId) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'tiffins':
            loadTiffins();
            break;
        case 'history':
            loadHistory();
            break;
        case 'invoices':
            loadInvoices();
            break;
        case 'profile':
            loadProfile();
            break;
        case 'admin-dashboard':
            loadAdminDashboard();
            break;
        case 'manage-users':
            loadManageUsers();
            break;
        case 'manage-tiffins':
            loadManageTiffins();
            break;
        case 'notices-polls':
            loadNoticesPolls();
            break;
        case 'generate-invoices':
            loadGenerateInvoices();
            break;
    }
    
    // Close sidebar on mobile
    if (window.innerWidth < 992) {
        document.querySelector('.sidebar').classList.remove('active');
    }
}

// ================================================
// DASHBOARD FUNCTIONS
// ================================================

async function loadDashboard() {
    console.log("Loading dashboard");
    
    // Load notices
    loadNotices();
    
    // Load polls
    loadPolls();
    
    // Load today's tiffin status
    loadTodayTiffin();
    
    // Load upcoming tiffins
    loadUpcomingTiffins();
}

async function loadNotices() {
    try {
        console.log("Loading notices");
        
        const notices = await apiRequest('/user/notices');
        
        console.log(`Loaded ${notices.length} notices`);
        
        const noticesContainer = document.getElementById('notices-container');
        
        if (notices.length === 0) {
            noticesContainer.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No notices">
                    <p>No active notices at the moment</p>
                </div>
            `;
            return;
        }
        
        // Sort notices by priority (highest first)
        notices.sort((a, b) => b.priority - a.priority);
        
        let noticesHTML = '';
        
        notices.forEach(notice => {
            const priorityClass = notice.priority === 0 ? 'normal' : notice.priority === 1 ? 'important' : 'urgent';
            const priorityText = notice.priority === 0 ? 'Normal' : notice.priority === 1 ? 'Important' : 'Urgent';
            
            noticesHTML += `
                <div class="notice-item">
                    <div class="notice-title">${notice.title}</div>
                    <div class="notice-content">${notice.content}</div>
                    <div class="notice-meta">
                        <span class="notice-priority ${priorityClass}">${priorityText}</span>
                        <span class="notice-date">${formatDate(notice.created_at)}</span>
                    </div>
                </div>
            `;
        });
        
        noticesContainer.innerHTML = noticesHTML;
    } catch (error) {
        console.error('Error loading notices:', error);
        document.getElementById('notices-container').innerHTML = `
            <div class="empty-state">
                <p>Error loading notices: ${error.message}</p>
            </div>
        `;
    }
}

// Update the poll display in loadPolls function
async function loadPolls() {
    try {
        console.log("Loading polls");
        
        const polls = await apiRequest('/user/polls');
        
        console.log(`Loaded ${polls.length} polls`);
        
        const pollsContainer = document.getElementById('polls-container');
        
        if (polls.length === 0) {
            pollsContainer.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No polls">
                    <p>No active polls at the moment</p>
                </div>
            `;
            return;
        }
        
        let pollsHTML = '';
        
        polls.forEach(poll => {
            let optionsHTML = '';
            
            if (userRole === 'admin') {
                // Show vote counts and percentages for admin
                poll.options.forEach((option, index) => {
                    const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);
                    const percentage = totalVotes > 0 ? Math.round((option.votes / totalVotes) * 100) : 0;
                    
                    optionsHTML += `
                        <div class="poll-option">
                            <span class="poll-option-label">${option.option}</span>
                            <div class="poll-option-progress">
                                <div class="poll-option-bar" style="width: ${percentage}%"></div>
                            </div>
                            <span class="poll-option-percentage">${percentage}% (${option.votes} votes)</span>
                        </div>
                    `;
                });
            } else {
                // For regular users, improved voting interface
                if (poll.has_voted) {
                    // If user has voted, show which option they chose
                    poll.options.forEach((option, index) => {
                        const isUserVote = index === poll.user_vote;
                        optionsHTML += `
                            <div class="poll-option ${isUserVote ? 'user-voted' : ''}">
                                <span class="poll-option-label">${option.option}</span>
                                ${isUserVote ? '<span class="user-vote-indicator">Your vote</span>' : ''}
                            </div>
                        `;
                    });
                } else {
                    // If user hasn't voted, show improved voting buttons
                    optionsHTML += `<div class="poll-vote-prompt">Please select an option:</div>`;
                    poll.options.forEach((option, index) => {
                        optionsHTML += `
                            <label class="poll-option-btn-container">
                                <input type="radio" name="poll-${poll._id}" value="${index}" class="poll-option-radio">
                                <span class="poll-option-btn-label">${option.option}</span>
                            </label>
                        `;
                    });
                    
                    // Add a submit button
                    optionsHTML += `
                        <button class="poll-submit-btn action-button" data-poll-id="${poll._id}">
                            Submit Vote
                        </button>
                    `;
                }
            }
            
            pollsHTML += `
                <div class="poll-item" data-poll-id="${poll._id}">
                    <div class="poll-question">${poll.question}</div>
                    <div class="poll-options">
                        ${optionsHTML}
                    </div>
                    <div class="poll-meta">
                        <span>Ends on ${formatDate(poll.end_date)}</span>
                        ${poll.has_voted && userRole !== 'admin' ? 
                            '<span class="poll-voted-badge">You voted</span>' : ''}
                    </div>
                </div>
            `;
        });
        
        pollsContainer.innerHTML = pollsHTML;
        
        // Add event listeners to vote buttons for users who haven't voted
        if (userRole !== 'admin') {
            document.querySelectorAll('.poll-submit-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    const pollId = e.target.dataset.pollId;
                    const selectedOption = document.querySelector(`input[name="poll-${pollId}"]:checked`);
                    
                    if (!selectedOption) {
                        showNotification('Please select an option before submitting', 'warning');
                        return;
                    }
                    
                    const optionIndex = parseInt(selectedOption.value);
                    
                    try {
                        await apiRequest(`/user/polls/${pollId}/vote?option_index=${optionIndex}`, {
                            method: 'POST'
                        });
                        
                        showNotification('Your vote has been recorded', 'success');
                        
                        // Reload polls to update UI
                        loadPolls();
                    } catch (error) {
                        console.error('Error submitting vote:', error);
                        showNotification('Failed to submit vote: ' + error.message, 'error');
                    }
                });
            });
        }
    } catch (error) {
        console.error('Error loading polls:', error);
        document.getElementById('polls-container').innerHTML = `
            <div class="empty-state">
                <p>Error loading polls: ${error.message}</p>
            </div>
        `;
    }
}

async function loadTodayTiffin() {
    try {
        console.log("Loading today's tiffin");
        
        // Since the specific endpoint is giving an error, let's use the general endpoint with today's date
        const today = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
        const response = await apiRequest(`/user/tiffins?date=${today}`);
        
        console.log("Today's tiffins response:", response);
        
        // The API returns data in a paginated format
        const tiffins = response.data || [];
        
                console.log(`Loaded ${tiffins.length} tiffins for today`);
        
        const todayTiffinStatus = document.getElementById('today-tiffin-status');
        const nextDeliveryTime = document.getElementById('next-delivery-time');
        
        if (!todayTiffinStatus || !nextDeliveryTime) {
            console.error("Today's tiffin elements not found");
            return;
        }
        
        if (tiffins.length === 0) {
            todayTiffinStatus.textContent = 'No tiffin scheduled for today';
            nextDeliveryTime.textContent = 'N/A';
            return;
        }
        
        // Find the next tiffin based on current time
        const now = new Date();
        const currentHour = now.getHours();
        
        tiffins.sort((a, b) => {
            const timeA = a.time === 'morning' ? 0 : 1; // morning = 0, evening = 1
            const timeB = b.time === 'morning' ? 0 : 1; // morning = 0, evening = 1
            return timeA - timeB;
        });
        // Get the first non-cancelled tiffin
        const nextTiffin = tiffins.find(tiffin => tiffin.status !== 'cancelled');
        
        // Update today's tiffin status
        if (nextTiffin) {
            todayTiffinStatus.textContent = formatTiffinStatus(nextTiffin.status);
            
            // Update next delivery time
            nextDeliveryTime.textContent = formatTiffinTime(nextTiffin.time);
        } else {
            todayTiffinStatus.textContent = 'No tiffin scheduled for today';
            nextDeliveryTime.textContent = 'N/A';
        }
    } catch (error) {
        console.error('Error loading today\'s tiffin:', error);
        const todayTiffinStatus = document.getElementById('today-tiffin-status');
        const nextDeliveryTime = document.getElementById('next-delivery-time');
        
        if (todayTiffinStatus) {
            todayTiffinStatus.textContent = 'Error loading tiffin';
        }
        if (nextDeliveryTime) {
            nextDeliveryTime.textContent = 'N/A';
        }
    }
}

async function loadUpcomingTiffins() {
    try {
        console.log("Loading upcoming tiffins");
        
        const upcomingTiffinsElement = document.getElementById('upcoming-tiffins');
        if (!upcomingTiffinsElement) {
            console.error("Element 'upcoming-tiffins' not found");
            return;
        }
        
        // Get today's date
        const today = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
        const response = await apiRequest(`/user/tiffins?date=${today}`);
        
        console.log("Upcoming tiffins response:", response);
        
        // The API returns data in a paginated format
        const tiffins = response.data || [];
        
        // Filter to include only future tiffins (today and later)
        const upcomingTiffins = tiffins.filter(tiffin => {
            return tiffin.date >= today && tiffin.status !== 'cancelled';
        });
        
        console.log(`Found ${upcomingTiffins.length} upcoming tiffins after filtering`);
        
        if (upcomingTiffins.length === 0) {
            upcomingTiffinsElement.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No upcoming tiffins">
                    <p>No upcoming tiffins scheduled</p>
                </div>
            `;
            return;
        }
        
        // Sort by date (ascending)
        upcomingTiffins.sort((a, b) => {
            if (a.date !== b.date) {
                return a.date.localeCompare(b.date);
            }
            // If same date, sort by time (morning first, evening second)
            const timeOrder = { 'morning': 0, 'evening': 1 };
            return timeOrder[a.time] - timeOrder[b.time];
        });
        let tiffinsHTML = '';
        
        // Limit to next 6 tiffins
        const nextTiffins = upcomingTiffins.slice(0, 6);
        
        nextTiffins.forEach(tiffin => {
            // Skip if tiffin doesn't have required properties
            if (!tiffin._id || !tiffin.time || !tiffin.status || !tiffin.date) {
                console.warn('Skipping invalid tiffin:', tiffin);
                return;
            }
            
            const statusClass = `status-${tiffin.status}`;
            
            tiffinsHTML += `
                <div class="tiffin-card" data-tiffin-id="${tiffin._id}">
                    <div class="tiffin-header">
                        <span class="tiffin-time">${formatTiffinTime(tiffin.time)}</span>
                        <span class="tiffin-status ${statusClass}">${formatTiffinStatus(tiffin.status)}</span>
                    </div>
                    <div class="tiffin-body">
                        <div class="tiffin-date">${formatDate(tiffin.date)}</div>
                        ${userRole === 'admin' && tiffin.description ? 
                            `<div class="tiffin-description">${tiffin.description}</div>` : ''}
                        <div class="tiffin-meta">
                            <span class="tiffin-cancellation-time">Cancel by ${formatTime(tiffin.cancellation_time || '00:00')}</span>
                            <span class="tiffin-price">₹${(tiffin.price || 0).toFixed(2)}</span>
                        </div>
                        <div class="tiffin-actions">
                            <button class="cancel-tiffin-btn secondary-button" data-tiffin-id="${tiffin._id}">Cancel</button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        if (tiffinsHTML === '') {
            upcomingTiffinsElement.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No upcoming tiffins">
                    <p>No valid upcoming tiffins found</p>
                </div>
            `;
            return;
        }
        
        upcomingTiffinsElement.innerHTML = tiffinsHTML;
        
        // Add event listeners to tiffin cards
        document.querySelectorAll('.tiffin-card').forEach(card => {
            card.addEventListener('click', (e) => {
                if (!e.target.classList.contains('cancel-tiffin-btn')) {
                    const tiffinId = e.currentTarget.dataset.tiffinId;
                    if (tiffinId) {
                        showTiffinDetails(tiffinId);
                    }
                }
            });
        });
        
        // Add event listeners to cancel buttons
        document.querySelectorAll('.cancel-tiffin-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const tiffinId = e.target.dataset.tiffinId;
                cancelTiffin(tiffinId);
            });
        });
        
        // Update month tiffin count from dashboard stats
        try {
            const dashboardStats = await apiRequest('/user/dashboard/stats');
            if (dashboardStats && dashboardStats.month_tiffins !== undefined) {
                document.getElementById('month-tiffin-count').textContent = `${dashboardStats.month_tiffins} tiffins`;
            } else {
                document.getElementById('month-tiffin-count').textContent = '0 tiffins';
            }
        } catch (statsError) {
            console.error('Error loading dashboard stats:', statsError);
            document.getElementById('month-tiffin-count').textContent = '0 tiffins';
        }
        
    } catch (error) {
        console.error('Error loading upcoming tiffins:', error);
        const upcomingTiffinsElement = document.getElementById('upcoming-tiffins');
        if (upcomingTiffinsElement) {
            upcomingTiffinsElement.innerHTML = `
                <div class="empty-state">
                    <img src="${createPlaceholderSVG('Error')}" alt="Error">
                    <p>Could not load upcoming tiffins: ${error.message}</p>
                </div>
            `;
        }
        document.getElementById('month-tiffin-count').textContent = '0 tiffins';
    }
}

// ================================================
// TIFFINS PAGE FUNCTIONS
// ================================================

async function loadTiffins() {
    try {
        console.log("Loading tiffins with API key:", apiKey ? "Present" : "Missing");
        
        const response = await apiRequest('/user/tiffins');
        
        console.log("Tiffins response:", response);
        
        // The API returns data in a paginated format
        const tiffins = response.data || [];
        console.log(`Loaded ${tiffins.length} tiffins`);
        
        displayTiffins(tiffins);
        
    } catch (error) {
        console.error('Error loading tiffins:', error);
        document.getElementById('tiffins-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading tiffins: ${error.message}</p>
            </div>
        `;
    }
}

function displayTiffins(tiffins, filters = {}) {
    const tiffinsList = document.getElementById('tiffins-list');
    
    // Apply filters
    let filteredTiffins = tiffins;
    
    if (filters.date) {
        filteredTiffins = filteredTiffins.filter(tiffin => tiffin.date === filters.date);
    }
    
    if (filters.time) {
        filteredTiffins = filteredTiffins.filter(tiffin => tiffin.time === filters.time);
    }
    
    if (filters.status) {
        filteredTiffins = filteredTiffins.filter(tiffin => tiffin.status === filters.status);
    }
    
    // Sort by date (newest first)
    filteredTiffins.sort((a, b) => {
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        if (dateA.getTime() !== dateB.getTime()) {
            return dateB - dateA;
        }
        return a.cancellation_time.localeCompare(b.cancellation_time);
    });
    
    if (filteredTiffins.length === 0) {
        tiffinsList.innerHTML = `
            <div class="empty-state">
                <img src="empty.svg" alt="No tiffins">
                <p>No tiffins found</p>
            </div>
        `;
        return;
    }
    
    let tiffinsHTML = '';
    
    filteredTiffins.forEach(tiffin => {
        const statusClass = `status-${tiffin.status}`;
        
        tiffinsHTML += `
            <div class="tiffin-card" data-tiffin-id="${tiffin._id}">
                <div class="tiffin-header">
                    <span class="tiffin-time">${formatTiffinTime(tiffin.time)}</span>
                    <span class="tiffin-status ${statusClass}">${formatTiffinStatus(tiffin.status)}</span>
                </div>
                <div class="tiffin-body">
                    <div class="tiffin-date">${formatDate(tiffin.date)}</div>
                    ${userRole === 'admin' && tiffin.description ? 
                        `<div class="tiffin-description">${tiffin.description}</div>` : ''}
                    <div class="tiffin-meta">
                        <span class="tiffin-cancellation-time">Cancel by ${formatTime(tiffin.cancellation_time || '00:00')}</span>
                        <span class="tiffin-price">₹${(tiffin.price || 0).toFixed(2)}</span>
                    </div>
                    <div class="tiffin-actions">
                        <button class="cancel-tiffin-btn secondary-button" data-tiffin-id="${tiffin._id}">Cancel</button>
                    </div>
                </div>
            </div>
        `;
    });
    
    tiffinsList.innerHTML = tiffinsHTML;
    
    // Add event listeners to tiffin cards
    document.querySelectorAll('.tiffin-card').forEach(card => {
        card.addEventListener('click', (e) => {
            if (!e.target.classList.contains('cancel-tiffin-btn')) {
                const tiffinId = e.currentTarget.dataset.tiffinId;
                showTiffinDetails(tiffinId);
            }
        });
    });
    
    // Add event listeners to cancel buttons
    document.querySelectorAll('.cancel-tiffin-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const tiffinId = e.target.dataset.tiffinId;
            cancelTiffin(tiffinId);
        });
    });
}

async function showTiffinDetails(tiffinId) {
    try {
        if (!tiffinId || typeof tiffinId !== 'string') {
            throw new Error('Invalid tiffin ID');
        }
        
        console.log(`Loading details for tiffin ID: ${tiffinId}`);
        const tiffin = await fetchTiffinDetails(tiffinId);
        
        // Update modal with tiffin details
        document.getElementById('tiffin-details-date').textContent = formatDate(tiffin.date);
        document.getElementById('tiffin-details-time').textContent = formatTiffinTime(tiffin.time);
        
        // Only show description for admin
        const descriptionSection = document.getElementById('tiffin-details-description-section');
        if (userRole === 'admin' && tiffin.description) {
            descriptionSection.classList.remove('hidden');
            document.getElementById('tiffin-details-description').textContent = tiffin.description || 'No description available';
        } else {
            descriptionSection.classList.add('hidden');
        }
        
        document.getElementById('tiffin-details-price').textContent = `₹${(tiffin.price || 0).toFixed(2)}`;
        document.getElementById('tiffin-details-cancellation-time').textContent = formatTime(tiffin.cancellation_time || '00:00');
        
        // Update status with appropriate class
        const statusElement = document.getElementById('tiffin-details-status');
        statusElement.textContent = formatTiffinStatus(tiffin.status);
        statusElement.className = `status-${tiffin.status}`;
        
        // Load cancellations if available
        await loadTiffinCancellations(tiffinId);
        
        // Update assigned users (for admin only)
        const usersContainer = document.getElementById('tiffin-details-users');
        if (usersContainer) {
            usersContainer.innerHTML = '';
            
            if (userRole === 'admin' && tiffin.assigned_users && tiffin.assigned_users.length > 0) {
                tiffin.assigned_users.forEach(userId => {
                    const userDiv = document.createElement('div');
                                        userDiv.className = 'assigned-user';
                    userDiv.textContent = userId;
                    usersContainer.appendChild(userDiv);
                });
            } else if (userRole === 'admin') {
                usersContainer.innerHTML = '<div class="empty-message">No users assigned</div>';
            } else {
                // Hide the assigned users section for regular users
                const userSection = document.querySelector('.tiffin-details-section.admin-only');
                if (userSection) {
                    userSection.style.display = 'none';
                }
            }
        }
        
        // Show/hide appropriate action buttons based on role and tiffin status
        const adminActions = document.querySelector('.tiffin-details-actions.admin-only');
        const userActions = document.querySelector('.tiffin-details-actions.user-only');
        
        if (userRole === 'admin') {
            if (adminActions) adminActions.style.display = 'block';
            if (userActions) userActions.style.display = 'none';
        } else {
            if (adminActions) adminActions.style.display = 'none';
            if (userActions) userActions.style.display = 'block';
            
            // Hide cancel button if tiffin is already delivered or cancelled
            // or if past cancellation time
            const cancelBtn = document.getElementById('cancel-tiffin-btn');
            if (cancelBtn) {
                if (tiffin.status === 'delivered' || tiffin.status === 'cancelled') {
                    cancelBtn.style.display = 'none';
                } else {
                    // Check if past cancellation time
                    const today = new Date().toISOString().split('T')[0];
                    const isTodayOrFuture = tiffin.date >= today;
                    
                    if (isTodayOrFuture) {
                        const now = new Date();
                        const cancellationTime = new Date(`${tiffin.date}T${tiffin.cancellation_time || '00:00'}`);
                        
                        if (now > cancellationTime) {
                            cancelBtn.style.display = 'none';
                        } else {
                            cancelBtn.style.display = 'block';
                            
                            // Add event listener to cancel button
                            cancelBtn.onclick = () => cancelTiffin(tiffin._id);
                        }
                    } else {
                        cancelBtn.style.display = 'none';
                    }
                }
            }
        }
        
        // Store the current tiffin ID for later use
        const modal = document.getElementById('tiffin-details-modal');
        if (modal) {
            modal.dataset.tiffinId = tiffin._id;
            modal.classList.add('active');
            
            // Ensure close button works properly
            const closeBtn = modal.querySelector('.close-modal');
            if (closeBtn) {
                // Clear all existing event listeners
                const newCloseBtn = closeBtn.cloneNode(true);
                closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
                
                // Add new event listener
                newCloseBtn.addEventListener('click', () => {
                    modal.classList.remove('active');
                });
            }
            
            // Apply the fix for admin users
            if (userRole === 'admin') {
                // Add a small delay to ensure the modal is fully rendered
                setTimeout(fixTiffinStatusUpdate, 100);
            }
        }
        
    } catch (error) {
        console.error('Error showing tiffin details:', error);
        showNotification('Could not load tiffin details: ' + (error.message || 'Unknown error'), 'error');
    }
}

async function loadTiffinCancellations(tiffinId) {
    try {
        const response = await fetch(`${API_BASE_URL}/user/tiffins/${tiffinId}/cancellations`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load cancellation information');
        }
        
        const data = await response.json();
        const cancellations = data.cancellations || [];
        
        // Find the cancellations section in the tiffin details modal
        const cancellationsSection = document.getElementById('tiffin-details-cancellations');
        
        if (cancellationsSection) {
            if (cancellations.length === 0) {
                cancellationsSection.innerHTML = '<p>No cancellations for this tiffin</p>';
            } else {
                let html = '<h3>Cancellations</h3><ul class="cancellations-list">';
                
                cancellations.forEach(cancellation => {
                    html += `
                        <li class="cancellation-item">
                            <span class="cancellation-user">${cancellation.name} (${cancellation.email})</span>
                            <span class="cancellation-time">Cancelled on ${formatDate(cancellation.cancelled_at)}</span>
                        </li>
                    `;
                });
                
                html += '</ul>';
                cancellationsSection.innerHTML = html;
            }
            
            // Make sure cancellations section is visible
            cancellationsSection.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Error loading cancellations:', error);
        // Just hide the section on error
        const cancellationsSection = document.getElementById('tiffin-details-cancellations');
        if (cancellationsSection) {
            cancellationsSection.classList.add('hidden');
        }
    }
}

// Add this function to fix the update status functionality
function fixTiffinStatusUpdate() {
    console.log("Fixing tiffin status update functionality");
    
    // Check if we're on the tiffin details modal
    const modal = document.getElementById('tiffin-details-modal');
    if (!modal || !modal.classList.contains('active')) {
        console.log("Tiffin details modal not active");
        return;
    }
    
    // Get the tiffin ID from the modal
    const tiffinId = modal.dataset.tiffinId;
    if (!tiffinId) {
        console.log("No tiffin ID found in modal");
        return;
    }
    
    console.log("Tiffin ID:", tiffinId);
    
    // Find the admin actions section
    const adminActions = modal.querySelector('.tiffin-details-actions.admin-only');
    if (!adminActions) {
        console.log("Admin actions section not found");
        return;
    }
    
    // Clear existing content
    adminActions.innerHTML = '';
    
    // Create a simple select element and update button
    const statusSelect = document.createElement('select');
    statusSelect.id = 'tiffin-status-select';
    statusSelect.className = 'form-control';
    
    // Add status options
    const statuses = [
        { value: 'scheduled', text: 'Scheduled' },
        { value: 'preparing', text: 'Preparing' },
        { value: 'prepared', text: 'Prepared' },
        { value: 'out_for_delivery', text: 'Out for Delivery' },
        { value: 'delivered', text: 'Delivered' },
        { value: 'cancelled', text: 'Cancelled' }
    ];
    
    statuses.forEach(status => {
        const option = document.createElement('option');
        option.value = status.value;
        option.textContent = status.text;
        statusSelect.appendChild(option);
    });
    
    // Create update button
    const updateButton = document.createElement('button');
    updateButton.textContent = 'Update Status';
    updateButton.className = 'action-button';
    updateButton.style.marginLeft = '10px';
    
    // Add event listener to the button
    updateButton.onclick = async () => {
        const newStatus = statusSelect.value;
        console.log("Updating tiffin status to:", newStatus);
        
        try {
            showNotification('Updating tiffin status...', 'info');
            
            const response = await fetch(`${API_BASE_URL}/admin/tiffins/${tiffinId}/status?status=${newStatus}`, {
                method: 'PUT',
                headers: {
                    'X-API-Key': apiKey
                }
            });
            
            console.log("Status update response:", response.status);
            
            if (!response.ok) {
                const error = await response.json();
                console.error("Status update error:", error);
                throw new Error(error.detail || 'Failed to update tiffin status');
            }
            
            const result = await response.json();
            console.log("Status update result:", result);
            
            showNotification('Tiffin status updated successfully', 'success');
            
            // Update status in modal
            const statusElement = document.getElementById('tiffin-details-status');
            if (statusElement) {
                statusElement.textContent = formatTiffinStatus(newStatus);
                statusElement.className = `status-${newStatus}`;
            }
            
            // Reload appropriate page
            if (document.getElementById('manage-tiffins-page').classList.contains('active')) {
                loadExistingTiffins();
            } else if (document.getElementById('tiffins-page').classList.contains('active')) {
                loadTiffins();
            } else if (document.getElementById('dashboard-page').classList.contains('active')) {
                loadDashboard();
            }
            
        } catch (error) {
            console.error('Error updating tiffin status:', error);
            showNotification('Error: ' + error.message, 'error');
        }
    };
    
    // Add elements to admin actions
    const container = document.createElement('div');
    container.style.display = 'flex';
    container.style.alignItems = 'center';
    container.appendChild(statusSelect);
    container.appendChild(updateButton);
    
    adminActions.appendChild(container);
    
    console.log("Status update functionality fixed and implemented");
}

async function fetchTiffinDetails(tiffinId) {
    try {
        console.log(`Fetching details for tiffin ID: ${tiffinId}, user role: ${userRole}`);
        
        // For user role, we'll use the user/tiffins endpoint
        // For admin role, we'll use the admin/tiffins/{tiffin_id} endpoint
        
        let tiffin;
        
        if (userRole === 'admin') {
            tiffin = await apiRequest(`/admin/tiffins/${tiffinId}`);
        } else {
            // For users, we now have an endpoint to get a specific tiffin
            tiffin = await apiRequest(`/user/tiffins/${tiffinId}`);
        }
        
        console.log("Tiffin details loaded:", tiffin);
        return tiffin;
    } catch (error) {
        console.error(`Error fetching tiffin details for ID ${tiffinId}:`, error);
        throw new Error(`Failed to load tiffin details: ${error.message}`);
    }
}

async function cancelTiffin(tiffinId) {
    try {
        if (!tiffinId) {
            showNotification('Invalid tiffin ID', 'error');
            return;
        }

        showConfirmDialog(
            'Cancel Tiffin',
            'Are you sure you want to cancel this tiffin? This action cannot be undone.',
            async () => {
                try {
                    // The API expects tiffin_id as a query parameter
                    await apiRequest(`/user/cancel-tiffin?tiffin_id=${tiffinId}`, {
                        method: 'POST'
                    });
                    
                    showNotification('Tiffin cancelled successfully', 'success');
                    
                    // Close modal if it's open
                    const modal = document.getElementById('tiffin-details-modal');
                    if (modal && modal.classList.contains('active')) {
                        modal.classList.remove('active');
                    }
                    
                    // Reload tiffins
                    if (document.getElementById('tiffins-page').classList.contains('active')) {
                        loadTiffins();
                    } else if (document.getElementById('dashboard-page').classList.contains('active')) {
                        loadDashboard();
                    }
                } catch (error) {
                    console.error('Error cancelling tiffin:', error);
                    showNotification('Failed to cancel tiffin: ' + error.message, 'error');
                }
            }
        );
    } catch (error) {
        console.error('Error cancelling tiffin:', error);
        showNotification('Error: ' + error.message, 'error');
    }
}

// ================================================
// HISTORY PAGE FUNCTIONS
// ================================================

async function loadHistory() {
    try {
        console.log("Loading history with API key:", apiKey ? "Present" : "Missing");
        
        const response = await apiRequest('/user/history');
        
        console.log("History response:", response);
        
        // The API returns data in a paginated format
        const history = response.data || [];
        console.log(`Loaded ${history.length} history items`);
        
        displayHistory(history);
        updateHistoryStats(history);
        
    } catch (error) {
        console.error('Error loading history:', error);
        document.getElementById('history-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading history: ${error.message}</p>
            </div>
        `;
    }
}

function displayHistory(history, filters = {}) {
    const historyList = document.getElementById('history-list');
    
    // Apply filters
    let filteredHistory = history;
    
    if (filters.startDate) {
        filteredHistory = filteredHistory.filter(item => item.date >= filters.startDate);
    }
    
    if (filters.endDate) {
        filteredHistory = filteredHistory.filter(item => item.date <= filters.endDate);
    }
    
    // Sort by date (newest first)
    filteredHistory.sort((a, b) => {
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        return dateB - dateA;
    });
    
    if (filteredHistory.length === 0) {
        historyList.innerHTML = `
            <div class="empty-state">
                <img src="empty.svg" alt="No history">
                <p>No tiffin history found</p>
            </div>
        `;
        return;
    }
    
    let historyHTML = '';
    
    filteredHistory.forEach(item => {
        const statusClass = `status-${item.status}`;
        
        historyHTML += `
            <div class="tiffin-card" data-tiffin-id="${item._id}">
                <div class="tiffin-header">
                    <span class="tiffin-time">${formatTiffinTime(item.time)}</span>
                    <span class="tiffin-status ${statusClass}">${formatTiffinStatus(item.status)}</span>
                </div>
                <div class="tiffin-body">
                    <div class="tiffin-date">${formatDate(item.date)}</div>
                    ${userRole === 'admin' && item.description ? 
                        `<div class="tiffin-description">${item.description}</div>` : ''}
                    <div class="tiffin-meta">
                        <span class="tiffin-cancellation-time">Cancel by ${formatTime(item.cancellation_time || '00:00')}</span>
                        <span class="tiffin-price">₹${(item.price || 0).toFixed(2)}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    historyList.innerHTML = historyHTML;
    
    // Add event listeners to tiffin cards
            document.querySelectorAll('.tiffin-card').forEach(card => {
            card.addEventListener('click', (e) => {
                const tiffinId = e.currentTarget.dataset.tiffinId;
                showTiffinDetails(tiffinId);
            });
        });
    }

function updateHistoryStats(history) {
    if (!Array.isArray(history)) {
        console.error('History is not an array:', history);
        document.getElementById('total-tiffins-count').textContent = '0';
        document.getElementById('total-tiffins-spent').textContent = '₹0.00';
        document.getElementById('most-ordered-time').textContent = 'N/A';
        return;
    }
    
    // Total tiffins
    const totalTiffins = history.filter(item => item.status !== 'cancelled').length;
    document.getElementById('total-tiffins-count').textContent = totalTiffins;
    
    // Total spent
    const totalSpent = history
        .filter(item => item.status !== 'cancelled')
        .reduce((sum, item) => sum + (item.price || 0), 0);
    document.getElementById('total-tiffins-spent').textContent = `₹${totalSpent.toFixed(2)}`;
    
    // Most ordered time
    const timeCounts = history
        .filter(item => item.status !== 'cancelled')
        .reduce((counts, item) => {
            if (item.time) {
                counts[item.time] = (counts[item.time] || 0) + 1;
            }
            return counts;
        }, {});
    
    let mostOrderedTime = 'N/A';
    let maxCount = 0;
    
    for (const [time, count] of Object.entries(timeCounts)) {
        if (count > maxCount) {
            mostOrderedTime = time;
            maxCount = count;
        }
    }
    
    document.getElementById('most-ordered-time').textContent = formatTiffinTime(mostOrderedTime);
}

// ================================================
// INVOICES PAGE FUNCTIONS
// ================================================

async function loadInvoices() {
    try {
        console.log("Loading invoices with API key:", apiKey ? "Present" : "Missing");
        
        const invoices = await apiRequest('/user/invoices');
        console.log(`Loaded ${invoices.length} invoices`);
        
        const invoicesList = document.getElementById('invoices-list');
        
        if (!invoices || invoices.length === 0) {
            invoicesList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No invoices">
                    <p>No invoices found</p>
                </div>
            `;
            return;
        }
        
        // Sort by date (newest first)
        invoices.sort((a, b) => {
            const dateA = new Date(a.generated_at || a.created_at || 0);
            const dateB = new Date(b.generated_at || b.created_at || 0);
            return dateB - dateA;
        });
        
        let invoicesHTML = '';
        
        invoices.forEach(invoice => {
            const statusClass = invoice.paid ? 'paid' : 'unpaid';
            const statusText = invoice.paid ? 'Paid' : 'Unpaid';
            
            invoicesHTML += `
                <div class="invoice-card" data-invoice-id="${invoice._id}">
                    <div class="invoice-card-header">
                        <span>Invoice #${invoice._id.substring(0, 8)}</span>
                        <span class="invoice-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="invoice-card-body">
                        <div class="invoice-card-dates">
                            <div class="invoice-card-date">
                                From
                                <span>${formatDate(invoice.start_date)}</span>
                            </div>
                            <div class="invoice-card-date">
                                To
                                <span>${formatDate(invoice.end_date)}</span>
                            </div>
                        </div>
                        <div class="invoice-card-tiffins">
                            <div class="invoice-card-tiffins-title">Total Tiffins</div>
                            <div class="invoice-card-tiffin-count">${invoice.tiffin_count || invoice.tiffins?.length || 0}</div>
                        </div>
                        <div class="invoice-card-total">
                            <span>Total Amount</span>
                            <span class="invoice-card-amount">₹${invoice.total_amount.toFixed(2)}</span>
                        </div>
                        <button class="secondary-button view-invoice-btn" data-invoice-id="${invoice._id}">
                            View Details
                        </button>
                    </div>
                </div>
            `;
        });
        
        invoicesList.innerHTML = invoicesHTML;
        
        // Add event listeners to view invoice buttons
        document.querySelectorAll('.view-invoice-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const invoiceId = e.target.dataset.invoiceId;
                viewInvoiceDetails(invoiceId);
            });
        });
        
    } catch (error) {
        console.error('Error loading invoices:', error);
        document.getElementById('invoices-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading invoices: ${error.message}</p>
            </div>
        `;
    }
}

async function viewInvoiceDetails(invoiceId) {
    try {
        console.log(`Loading details for invoice ID: ${invoiceId}`);
        
        const invoice = await apiRequest(`/user/invoices/${invoiceId}`);
        console.log("Invoice details loaded:", invoice);
        
        // Create a modal dynamically
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.id = 'invoice-details-modal';
        
        let tiffinsHTML = '';
        if (invoice.tiffin_details && invoice.tiffin_details.length > 0) {
            invoice.tiffin_details.forEach(tiffin => {
                tiffinsHTML += `
                    <div class="invoice-tiffin-item">
                        <div class="invoice-tiffin-date">
                            <strong>${formatDate(tiffin.date)}</strong> (${formatTiffinTime(tiffin.time)})
                        </div>
                        <div class="invoice-tiffin-desc">${userRole === 'admin' && tiffin.description ? tiffin.description : 'Tiffin'}</div>
                        <div class="invoice-tiffin-price">₹${tiffin.price.toFixed(2)}</div>
                    </div>
                `;
            });
        } else {
            tiffinsHTML = '<div class="empty-message">No tiffin details available</div>';
        }
        
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Invoice Details</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="invoice-details-header">
                        <div class="invoice-details-id">
                            <strong>Invoice #:</strong> ${invoice._id.substring(0, 8)}
                        </div>
                        <div class="invoice-details-status ${invoice.paid ? 'paid' : 'unpaid'}">
                            ${invoice.paid ? 'Paid' : 'Unpaid'}
                        </div>
                    </div>
                    
                    <div class="invoice-details-dates">
                        <div class="invoice-details-date">
                            <strong>Period:</strong> ${formatDate(invoice.start_date)} to ${formatDate(invoice.end_date)}
                        </div>
                        <div class="invoice-details-date">
                            <strong>Generated:</strong> ${formatDate(invoice.generated_at)}
                        </div>
                    </div>
                    
                    <div class="invoice-details-section">
                        <h3>Tiffins (${invoice.tiffin_details?.length || 0})</h3>
                        <div class="invoice-tiffins-list">
                            ${tiffinsHTML}
                        </div>
                    </div>
                    
                    <div class="invoice-details-total">
                        <strong>Total Amount:</strong> 
                        <span class="invoice-total-amount">₹${invoice.total_amount.toFixed(2)}</span>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Close button event
        modal.querySelector('.close-modal').addEventListener('click', () => {
            document.body.removeChild(modal);
        });
        
    } catch (error) {
        console.error('Error showing invoice details:', error);
        showNotification('Failed to load invoice details: ' + error.message, 'error');
    }
}

// ================================================
// PROFILE PAGE FUNCTIONS
// ================================================

async function loadProfile() {
    try {
        console.log("Loading profile");
        
        // Fetch latest user profile
        await fetchUserProfile();
        
        // Load profile stats
        await loadProfileStats();
        
    } catch (error) {
        console.error('Error loading profile:', error);
        showNotification('Failed to load profile data: ' + error.message, 'error');
    }
}

async function fetchUserProfile() {
    try {
        console.log("Fetching user profile, role:", userRole);
        
        // For admin users, create a basic profile if needed
        if (userRole === 'admin') {
            console.log("Admin user, creating default profile");
            currentUser = {
                name: "Administrator",
                user_id: "admin",
                email: "admin@tiffintreats.com",
                address: "TiffinTreats HQ"
            };
            
            // Update UI with admin info
            updateUserInfo();
            return currentUser;
        }
        
        console.log("Fetching profile with API key:", apiKey ? apiKey.substring(0, 5) + "..." : "Missing");
        
        const userProfile = await apiRequest('/user/profile');
        
        console.log("Profile data received:", userProfile);
        
        currentUser = userProfile;
        
        // Update UI with user info
        updateUserInfo();
        
        return userProfile;
    } catch (error) {
        console.error('Error fetching user profile:', error);
        showNotification('Failed to load profile: ' + error.message, 'error');
        throw error;
    }
}

async function updateUserProfile() {
    try {
        console.log("Updating user profile");
        
        const name = document.getElementById('profile-edit-name').value.trim();
        const email = document.getElementById('profile-edit-email').value.trim();
        const address = document.getElementById('profile-edit-address').value.trim();
        
        if (!name || !email || !address) {
            showNotification('Please fill in all fields', 'error');
            return;
        }
        
        const response = await apiRequest('/user/profile', {
            method: 'PUT',
            body: JSON.stringify({
                name,
                email,
                address
            })
        });
        
        // Refresh user profile
        await fetchUserProfile();
        
        showNotification('Profile updated successfully', 'success');
    } catch (error) {
        console.error('Error updating profile:', error);
        showNotification('Failed to update profile: ' + error.message, 'error');
    }
}

async function changePassword() {
    try {
        console.log("Changing password");
        
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        if (!currentPassword || !newPassword || !confirmPassword) {
            showNotification('Please fill in all password fields', 'error');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            showNotification('New passwords do not match', 'error');
            return;
        }
        
        // Update these parameter names to match the API's expected field names
        const response = await fetch(`${API_BASE_URL}/user/password`, {
            method: 'PUT',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                old_password: currentPassword,  // This must match the API's parameter name
                new_password: newPassword       // This must match the API's parameter name
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to change password');
        }
        
        // Clear password fields
        document.getElementById('current-password').value = '';
        document.getElementById('new-password').value = '';
        document.getElementById('confirm-password').value = '';
        
        showNotification('Password changed successfully', 'success');
    } catch (error) {
        console.error('Error changing password:', error);
        showNotification('Failed to change password: ' + error.message, 'error');
    }
}
async function loadProfileStats() {
    try {
        // For admin, we don't need to fetch stats
        if (userRole === 'admin') {
            document.getElementById('profile-total-tiffins').textContent = 'N/A';
            document.getElementById('profile-most-ordered').textContent = 'N/A';
            return;
        }
        
        // For regular users, fetch stats from API
        const stats = await apiRequest('/user/dashboard/stats');
        
        if (stats) {
            document.getElementById('profile-total-tiffins').textContent = stats.month_tiffins || '0';
            document.getElementById('profile-most-ordered').textContent = stats.favorite_time || 'None';
        }
    } catch (error) {
        console.error('Error loading user stats:', error);
        document.getElementById('profile-total-tiffins').textContent = 'Error';
        document.getElementById('profile-most-ordered').textContent = 'Error';
    }
}

function updateUserInfo() {
    if (!currentUser) {
        console.error("Cannot update user info: currentUser is not defined");
        return;
    }

    // Update user name and initial in sidebar
    document.getElementById('user-name').textContent = currentUser.name || 'User';
    document.getElementById('user-initial').textContent = getInitials(currentUser.name || 'User');
    
    // Update user role
    document.getElementById('user-role').textContent = userRole === 'admin' ? 'Administrator' : 'User';
    
    // Show/hide admin section based on role
    const adminSection = document.querySelector('.admin-section');
    if (adminSection) {
        if (userRole === 'admin') {
            adminSection.classList.remove('hidden');
        } else {
            adminSection.classList.add('hidden');
        }
    }
    
    // Update profile page if it exists
    updateProfilePage();
}

function updateProfilePage() {
    // Skip if profile page elements don't exist yet
    if (!document.getElementById('profile-name')) return;
    
    // Update profile information
    document.getElementById('profile-name').textContent = currentUser.name || 'User';
    document.getElementById('profile-user-id').textContent = currentUser.user_id || '';
    document.getElementById('profile-initial').textContent = getInitials(currentUser.name || 'User');
    
    // Update form fields
    document.getElementById('profile-edit-name').value = currentUser.name || '';
    document.getElementById('profile-edit-email').value = currentUser.email || '';
    document.getElementById('profile-edit-address').value = currentUser.address || '';
    
    // Update account statistics if available
    if (currentUser.created_at) {
        document.getElementById('member-since').textContent = formatDate(currentUser.created_at);
    }
}

// ================================================
// NOTIFICATION FUNCTIONS
// ================================================

async function loadNotifications() {
    try {
                const response = await apiRequest('/user/notifications');
        
        const notifications = response.notifications || [];
        const unreadCount = response.unread_count || 0;
        
        // Update notification count badge
        document.getElementById('notification-count').textContent = unreadCount;
        
        // Update notification list
        const notificationList = document.getElementById('notification-list');
        notificationList.innerHTML = '';
        
        if (notifications.length === 0) {
            notificationList.innerHTML = '<div class="empty-notification">No notifications</div>';
            return;
        }
        
        notifications.forEach(notification => {
            const notificationItem = document.createElement('div');
            notificationItem.className = `notification-item ${notification.read ? '' : 'unread'}`;
            notificationItem.dataset.id = notification._id;
            
            notificationItem.innerHTML = `
                <div class="notification-icon ${notification.type}">
                    <i class="icon-${notification.type}"></i>
                </div>
                <div class="notification-content">
                    <div class="notification-title">${notification.title}</div>
                    <div class="notification-message">${notification.message}</div>
                    <div class="notification-time">${formatDate(notification.created_at)}</div>
                </div>
            `;
            
            // Add click handler to mark as read
            notificationItem.addEventListener('click', () => {
                markNotificationRead(notification._id);
            });
            
            notificationList.appendChild(notificationItem);
        });
        
        // Update active notifications array for global access
        activeNotifications = notifications.filter(n => !n.read);
        
    } catch (error) {
        console.error('Error loading notifications:', error);
        document.getElementById('notification-list').innerHTML = 
            '<div class="empty-notification">Error loading notifications</div>';
    }
}

async function markNotificationRead(notificationId) {
    try {
        const response = await fetch(`${API_BASE_URL}/user/notifications/mark-read`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify([notificationId])  // Send as array directly, not as an object property
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to mark notification as read');
        }
        
        // Update UI
        const notificationItem = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
        if (notificationItem) {
            notificationItem.classList.remove('unread');
        }
        
        // Update global notification count
        const unreadCount = parseInt(document.getElementById('notification-count').textContent) - 1;
        document.getElementById('notification-count').textContent = Math.max(0, unreadCount);
        
        // Update active notifications array
        activeNotifications = activeNotifications.filter(n => n._id !== notificationId);
        
    } catch (error) {
        console.error('Error marking notification as read:', error);
        showNotification('Failed to mark notification as read: ' + error.message, 'error');
    }
}

async function markAllNotificationsRead() {
    try {
        await apiRequest('/user/notifications/mark-all-read', {
            method: 'POST'
        });
        
        // Update UI
        document.querySelectorAll('.notification-item.unread').forEach(item => {
            item.classList.remove('unread');
        });
        
        // Reset notification count
        document.getElementById('notification-count').textContent = '0';
        
        // Clear active notifications array
        activeNotifications = [];
        
        showNotification('All notifications marked as read', 'success');
        
    } catch (error) {
        console.error('Error marking all notifications as read:', error);
        showNotification('Failed to mark notifications as read', 'error');
    }
}

// ================================================
// ADMIN DASHBOARD FUNCTIONS
// ================================================

async function loadAdminDashboard() {
    if (userRole !== 'admin') return;
    
    try {
        console.log("Loading admin dashboard with API key:", apiKey ? "Present" : "Missing");
        
        const stats = await apiRequest('/admin/dashboard');
        
        console.log("Admin dashboard stats loaded:", stats);
        
        // Update dashboard stats
        document.getElementById('active-users-count').textContent = stats.total_users;
        document.getElementById('active-tiffins-count').textContent = stats.active_tiffins;
        document.getElementById('monthly-revenue').textContent = `₹${stats.monthly_revenue.toFixed(2)}`;
        document.getElementById('today-deliveries').textContent = stats.today_deliveries;
        
        // Additional stats that might be available
        if (stats.pending_requests) {
            const pendingRequestsBadge = document.createElement('span');
            pendingRequestsBadge.className = 'badge';
            pendingRequestsBadge.textContent = stats.pending_requests;
            document.querySelector('.quick-action-card[data-page="manage-tiffins"]').appendChild(pendingRequestsBadge);
        }
        
        if (stats.unpaid_invoices) {
            const unpaidInvoicesBadge = document.createElement('span');
            unpaidInvoicesBadge.className = 'badge';
            unpaidInvoicesBadge.textContent = stats.unpaid_invoices;
            document.querySelector('.quick-action-card[data-page="generate-invoices"]').appendChild(unpaidInvoicesBadge);
        }
        
        // Load pending requests
        loadPendingRequests();
        
        // Setup quick action links
        setupQuickActionLinks();
        
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
        showNotification('Failed to load dashboard stats: ' + error.message, 'error');
    }
}

async function loadPendingRequests() {
    if (userRole !== 'admin') return;
    
    try {
        console.log("Loading pending requests");
        
        const requests = await apiRequest('/admin/tiffin-requests?status=pending');
        
        console.log(`Loaded ${requests.length} pending requests`);
        
        const requestsList = document.getElementById('pending-requests-list');
        
        if (requests.length === 0) {
            requestsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No requests">
                    <p>No pending special requests</p>
                </div>
            `;
            return;
        }
        
        let requestsHTML = '';
        
        requests.forEach(request => {
            requestsHTML += `
                <div class="request-card">
                    <div class="request-header">
                        <span>Request from ${request.user_id}</span>
                        <span class="request-date">${formatDate(request.created_at)}</span>
                    </div>
                    <div class="request-body">
                        <div class="request-description">${request.description}</div>
                        <div class="request-details">
                            <div class="request-detail">
                                <span class="detail-label">Preferred Date:</span>
                                <span class="detail-value">${formatDate(request.preferred_date)}</span>
                            </div>
                            <div class="request-detail">
                                <span class="detail-label">Preferred Time:</span>
                                <span class="detail-value">${formatTiffinTime(request.preferred_time)}</span>
                            </div>
                            ${request.special_instructions ? `
                            <div class="request-detail">
                                <span class="detail-label">Special Instructions:</span>
                                <span class="detail-value">${request.special_instructions}</span>
                            </div>` : ''}
                        </div>
                        <div class="request-actions">
                            <button class="action-button approve-request-btn" data-request-id="${request._id}">Approve</button>
                            <button class="secondary-button reject-request-btn" data-request-id="${request._id}">Reject</button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        requestsList.innerHTML = requestsHTML;
        
        // Add event listeners to approve/reject buttons
        document.querySelectorAll('.approve-request-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const requestId = e.target.dataset.requestId;
                showApproveRequestModal(requestId);
            });
        });
        
        document.querySelectorAll('.reject-request-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const requestId = e.target.dataset.requestId;
                rejectRequest(requestId);
            });
        });
        
    } catch (error) {
        console.error('Error loading pending requests:', error);
        document.getElementById('pending-requests-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading requests: ${error.message}</p>
            </div>
        `;
    }
}

function setupQuickActionLinks() {
    document.querySelectorAll('.quick-action-card').forEach(card => {
        // Remove existing event listeners to prevent duplicates
        const newCard = card.cloneNode(true);
        card.parentNode.replaceChild(newCard, card);
        
        // Add new event listener
        newCard.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = newCard.getAttribute('data-page');
            if (pageId) {
                navigateTo(pageId);
            }
        });
    });
}

// ================================================
// USER MANAGEMENT FUNCTIONS (ADMIN)
// ================================================

async function loadManageUsers() {
    if (userRole !== 'admin') return;
    
    try {
        console.log("Loading manage users with API key:", apiKey ? "Present" : "Missing");
        
        const users = await apiRequest('/admin/users');
        
        console.log(`Loaded ${users.length} users`);
        
        displayUsers(users);
        
    } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('users-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading users: ${error.message}</p>
            </div>
        `;
    }
}

function displayUsers(users, searchQuery = '') {
    const usersList = document.getElementById('users-list');
    
    // Filter users by search query
    let filteredUsers = users;
    if (searchQuery) {
        const query = searchQuery.toLowerCase();
        filteredUsers = users.filter(user => 
            user.name.toLowerCase().includes(query) || 
            user.user_id.toLowerCase().includes(query) || 
            user.email.toLowerCase().includes(query)
        );
    }
    
    // Sort by name
    filteredUsers.sort((a, b) => a.name.localeCompare(b.name));
    
    if (filteredUsers.length === 0) {
        usersList.innerHTML = `
            <div class="empty-state">
                <img src="empty.svg" alt="No users">
                <p>No users found</p>
            </div>
        `;
        return;
    }
    
    let usersHTML = '';
    
    filteredUsers.forEach(user => {
        const statusClass = user.active ? 'active' : 'inactive';
        const statusText = user.active ? 'Active' : 'Inactive';
        
        usersHTML += `
            <div class="user-card" data-user-id="${user.user_id}">
                <div class="user-card-header">
                    <div class="user-avatar">
                        <span>${getInitials(user.name)}</span>
                    </div>
                    <div class="user-info">
                        <h3>${user.name}</h3>
                        <p>${user.user_id}</p>
                    </div>
                </div>
                <div class="user-card-body">
                    <div class="user-card-info">
                        <div class="user-card-label">Email</div>
                        <div class="user-card-value">${user.email}</div>
                    </div>
                    <div class="user-card-status">
                        <span class="user-status ${statusClass}">${statusText}</span>
                        <button class="secondary-button view-user-btn">View Details</button>
                    </div>
                </div>
            </div>
        `;
    });
    
    usersList.innerHTML = usersHTML;
    
    // Add event listeners to user cards
    document.querySelectorAll('.user-card').forEach(card => {
        card.addEventListener('click', (e) => {
            const userId = e.currentTarget.dataset.userId;
            showUserDetails(userId);
        });
    });
}

async function showUserDetails(userId) {
    if (userRole !== 'admin') return;
    
    try {
        console.log(`Loading details for user: ${userId}`);
        
        const user = await apiRequest(`/admin/users/${userId}`);
        console.log("User details loaded:", user);
        
        // Fetch user stats
        const stats = await apiRequest(`/admin/user/${userId}/stats`);
        console.log("User stats loaded:", stats);
        
        // Populate modal
        document.getElementById('user-details-name').textContent = user.name;
        document.getElementById('user-details-user-id').textContent = user.user_id;
        document.getElementById('user-details-user-email').textContent = user.email;
        document.getElementById('user-details-address').textContent = user.address;
        document.getElementById('user-details-initial').textContent = getInitials(user.name);
        
        // Stats
        document.getElementById('user-details-member-since').textContent = formatDate(stats.active_since);
        document.getElementById('user-details-total-tiffins').textContent = stats.total_tiffins;
        document.getElementById('user-details-cancelled-tiffins').textContent = stats.cancelled_tiffins;
        document.getElementById('user-details-total-spent').textContent = `₹${stats.total_spent.toFixed(2)}`;
        
        // Toggle button text based on user status
        const toggleStatusBtn = document.getElementById('toggle-user-status-btn');
        toggleStatusBtn.textContent = user.active ? 'Deactivate User' : 'Activate User';
        toggleStatusBtn.className = user.active ? 'warning-button' : 'action-button';
        
        // Populate edit form
        document.getElementById('edit-user-name').value = user.name;
        document.getElementById('edit-user-email').value = user.email;
        document.getElementById('edit-user-address').value = user.address;
        document.getElementById('edit-user-active').value = user.active.toString();
        
        // Setup event listeners
        setupUserDetailsListeners(user);
        
        // Show modal
        document.getElementById('user-details-modal').classList.add('active');
        
    } catch (error) {
        console.error('Error showing user details:', error);
        showNotification('Failed to load user details: ' + error.message, 'error');
    }
}

function setupUserDetailsListeners(user) {
    // Close button
    document.querySelector('#user-details-modal .close-modal').addEventListener('click', () => {
        document.getElementById('user-details-modal').classList.remove('active');
        document.querySelector('.user-details-content').classList.remove('hidden');
        document.querySelector('.edit-user-form').classList.add('hidden');
    });
    
    // Edit user button
    document.getElementById('edit-user-btn').onclick = () => {
        document.querySelector('.user-details-content').classList.add('hidden');
        document.querySelector('.edit-user-form').classList.remove('hidden');
    };
    
    // Cancel edit button
    document.getElementById('cancel-edit-user-btn').onclick = () => {
        document.querySelector('.user-details-content').classList.remove('hidden');
        document.querySelector('.edit-user-form').classList.add('hidden');
    };
    
    // Save user button
    document.getElementById('save-user-btn').onclick = async () => {
        try {
                        const name = document.getElementById('edit-user-name').value.trim();
            const email = document.getElementById('edit-user-email').value.trim();
            const address = document.getElementById('edit-user-address').value.trim();
            const active = document.getElementById('edit-user-active').value === 'true';
            
            if (!name || !email || !address) {
                showNotification('Please fill in all fields', 'error');
                return;
            }
            
            const response = await fetch(`${API_BASE_URL}/admin/users/${user.user_id}`, {
                method: 'PUT',
                headers: {
                    'X-API-Key': apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name,
                    email,
                    address,
                    active
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to update user');
            }
            
            showNotification('User updated successfully', 'success');
            document.getElementById('user-details-modal').classList.remove('active');
            
            // Reload users list
            loadManageUsers();
            
        } catch (error) {
            console.error('Error updating user:', error);
            showNotification(error.message, 'error');
        }
    };
    
    // Toggle user status button
    document.getElementById('toggle-user-status-btn').onclick = () => {
        const newStatus = !user.active;
        const actionText = newStatus ? 'activate' : 'deactivate';
        
        showConfirmDialog(
            `${newStatus ? 'Activate' : 'Deactivate'} User`,
            `Are you sure you want to ${actionText} this user?`,
            async () => {
                try {
                    const response = await fetch(`${API_BASE_URL}/admin/users/${user.user_id}`, {
                        method: 'PUT',
                        headers: {
                            'X-API-Key': apiKey,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            active: newStatus
                        })
                    });
                    
                    if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.detail || `Failed to ${actionText} user`);
                    }
                    
                    showNotification(`User ${actionText}d successfully`, 'success');
                    document.getElementById('user-details-modal').classList.remove('active');
                    
                    // Reload users list
                    loadManageUsers();
                    
                } catch (error) {
                    console.error(`Error ${actionText}ing user:`, error);
                    showNotification(error.message, 'error');
                }
            }
        );
    };
}

async function createUser() {
    try {
        const userId = document.getElementById('new-user-id').value.trim();
        const name = document.getElementById('new-user-name').value.trim();
        const email = document.getElementById('new-user-email').value.trim();
        const address = document.getElementById('new-user-address').value.trim();
        const password = document.getElementById('new-user-password').value;
        
        if (!userId || !name || !email || !address || !password) {
            showNotification('Please fill in all fields', 'error');
            return;
        }
        
        const user = {
            user_id: userId,
            name,
            email,
            address,
            password
        };
        
        const response = await fetch(`${API_BASE_URL}/admin/users`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(user)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create user');
        }
        
        showNotification('User created successfully', 'success');
        document.getElementById('add-user-modal').classList.remove('active');
        
        // Clear form
        document.getElementById('new-user-id').value = '';
        document.getElementById('new-user-name').value = '';
        document.getElementById('new-user-email').value = '';
        document.getElementById('new-user-address').value = '';
        document.getElementById('new-user-password').value = '';
        
        // Reload users
        loadManageUsers();
        
    } catch (error) {
        console.error('Error creating user:', error);
        showNotification(error.message, 'error');
    }
}

// ================================================
// TIFFIN MANAGEMENT FUNCTIONS (ADMIN)
// ================================================

async function loadManageTiffins() {
    if (userRole !== 'admin') return;
    
    console.log("Loading manage tiffins");
    
    // Load users for select dropdowns
    await loadUsersForSelect();
    
    // Load existing tiffins
    loadExistingTiffins();
    
    // Set up tab switching
    setupTiffinTabs();
    
    // Initialize forms
    setupCreateTiffinForm();
    setupBatchCreateTiffinForm();
}

function setupTiffinTabs() {
    const tiffinTabBtns = document.querySelectorAll('.tiffin-management-tabs .tab-btn');
    tiffinTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            console.log('Tiffin tab clicked:', this.getAttribute('data-tab'));
            
            // Remove active class from all tabs
            document.querySelectorAll('.tiffin-management-tabs .tab-btn').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Add active class to clicked tab
            this.classList.add('active');
            
            // Hide all tab panes
            document.querySelectorAll('#manage-tiffins-page .tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            
            // Show selected tab pane
            const tabId = this.getAttribute('data-tab');
            const targetPane = document.getElementById(`${tabId}-tab`);
            if (targetPane) {
                targetPane.classList.add('active');
                console.log('Activating pane:', tabId);
            } else {
                console.error('Could not find tab pane:', tabId);
            }
        });
    });
}

function setupCreateTiffinForm() {
    // Get the create tiffin form
    const createTiffinForm = document.getElementById('create-tiffin-tab');
    if (!createTiffinForm) return;
    
    // Remove delivery time section
    const deliveryTimeSection = createTiffinForm.querySelector('.form-group:has(#tiffin-delivery)');
    if (deliveryTimeSection) {
        deliveryTimeSection.remove();
    }
    
    // Update create tiffin button click handler
    const createTiffinBtn = document.getElementById('create-tiffin-btn');
    if (createTiffinBtn) {
        // Remove existing event listeners
        const newCreateTiffinBtn = createTiffinBtn.cloneNode(true);
        createTiffinBtn.parentNode.replaceChild(newCreateTiffinBtn, createTiffinBtn);
        
        // Add new event listener
        newCreateTiffinBtn.addEventListener('click', createTiffinWithoutMenuItems);
    }
}

// New function to create tiffin without menu items
async function createTiffinWithoutMenuItems() {
    try {
        const date = document.getElementById('tiffin-date').value;
        const time = document.getElementById('tiffin-time').value;
        const description = document.getElementById('tiffin-description').value.trim();
        const price = parseFloat(document.getElementById('tiffin-price').value);
        const cancellationTime = document.getElementById('tiffin-cancellation').value;
        
        // Get selected users
        const userSelect = document.getElementById('tiffin-users');
        const assignedUsers = Array.from(userSelect.selectedOptions).map(option => option.value);
        
        if (!date || !time || !description || isNaN(price) || !cancellationTime) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }
        
        if (assignedUsers.length === 0) {
            showNotification('Please assign at least one user', 'error');
            return;
        }
        
        const tiffin = {
            date,
            time,
            description,
            price,
            cancellation_time: cancellationTime,
            assigned_users: assignedUsers,
            status: "scheduled"
        };
        
        await apiRequest('/admin/tiffins', {
            method: 'POST',
            body: JSON.stringify(tiffin)
        });
        
        showNotification('Tiffin created successfully', 'success');
        
        // Clear form
        document.getElementById('tiffin-date').value = '';
        document.getElementById('tiffin-time').value = '';
        document.getElementById('tiffin-description').value = '';
        document.getElementById('tiffin-price').value = '';
        document.getElementById('tiffin-cancellation').value = '';
        
        // Deselect all users
        Array.from(userSelect.options).forEach(option => {
            option.selected = false;
        });
        
        // Switch to manage tab
        document.querySelector('.tab-btn[data-tab="manage-tiffin"]').click();
        
        // Reload tiffins
        loadExistingTiffins();
        
    } catch (error) {
        console.error('Error creating tiffin:', error);
        showNotification(error.message, 'error');
    }
}

function setupBatchCreateTiffinForm() {
    // Get the batch create tiffin form
    const batchCreateTiffinForm = document.getElementById('batch-create-tab');
    if (!batchCreateTiffinForm) return;
    
    // Remove delivery time section
    const deliveryTimeSection = batchCreateTiffinForm.querySelector('.form-group:has(#batch-tiffin-delivery)');
    if (deliveryTimeSection) {
        deliveryTimeSection.remove();
    }
    
    // Update batch create tiffin button click handler
    const batchCreateBtn = document.getElementById('batch-create-btn');
    if (batchCreateBtn) {
        // Remove existing event listeners
        const newBatchCreateBtn = batchCreateBtn.cloneNode(true);
        batchCreateBtn.parentNode.replaceChild(newBatchCreateBtn, batchCreateBtn);
        
        // Add new event listener
        newBatchCreateBtn.addEventListener('click', batchCreateTiffinsWithoutMenuItems);
    }
}

// New function to batch create tiffins without menu items
async function batchCreateTiffinsWithoutMenuItems() {
    try {
        const date = document.getElementById('batch-tiffin-date').value;
        const time = document.getElementById('batch-tiffin-time').value;
        const description = document.getElementById('batch-tiffin-description').value.trim();
        const price = parseFloat(document.getElementById('batch-tiffin-price').value);
        const cancellationTime = document.getElementById('batch-tiffin-cancellation').value;
        
        if (!date || !time || !description || isNaN(price) || !cancellationTime) {
            showNotification('Please fill in all tiffin details', 'error');
            return;
        }
        
        // Get user groups
        const userGroups = [];
        document.querySelectorAll('.user-group').forEach(group => {
            const select = group.querySelector('.user-group-select-input');
            const users = Array.from(select.selectedOptions).map(option => option.value);
            
            if (users.length > 0) {
                userGroups.push(users);
            }
        });
        
        if (userGroups.length === 0) {
            showNotification('Please add at least one user group with selected users', 'error');
            return;
        }
        
        const baseTiffin = {
            date,
            time,
            description,
            price,
            cancellation_time: cancellationTime,
            status: "scheduled"
        };
        
        // Show loading state
        const batchCreateBtn = document.getElementById('batch-create-btn');
        batchCreateBtn.disabled = true;
        batchCreateBtn.innerHTML = '<span class="spinner"></span> Creating...';
        
        // Make the API request
        const response = await fetch(`${API_BASE_URL}/admin/batch-tiffins`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                base_tiffin: baseTiffin,
                user_groups: userGroups
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to create batch tiffins');
        }
        
        showNotification('Batch tiffins created successfully', 'success');
        
        // Reset form and UI elements
        document.getElementById('batch-tiffin-date').value = '';
        document.getElementById('batch-tiffin-time').value = '';
        document.getElementById('batch-tiffin-description').value = '';
        document.getElementById('batch-tiffin-price').value = '';
        document.getElementById('batch-tiffin-cancellation').value = '';
        
        // Reset user groups
        resetUserGroups();
        
        // Switch to manage tab
        document.querySelector('.tab-btn[data-tab="manage-tiffin"]').click();
        
        // Reload tiffins
        loadExistingTiffins();
        
    } catch (error) {
        console.error('Error creating batch tiffins:', error);
        showNotification(error.message, 'error');
    } finally {
        // Reset button state
        const batchCreateBtn = document.getElementById('batch-create-btn');
        if (batchCreateBtn) {
            batchCreateBtn.disabled = false;
            batchCreateBtn.textContent = 'Create Batch Tiffins';
        }
    }
}

async function loadUsersForSelect() {
    try {
        console.log("Loading users for select dropdowns");
        
        const response = await fetch(`${API_BASE_URL}/admin/users`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Users for select response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Users for select error:", errorData);
            throw new Error(errorData.detail || 'Failed to load users');
        }
        
        const users = await response.json();
        console.log(`Loaded ${users.length} users for select`);
        
        // Filter active users and sort by name
        const activeUsers = users
            .filter(user => user.active)
            .sort((a, b) => a.name.localeCompare(b.name));
        
        // Populate user select for single tiffin
        const tiffinUsers = document.getElementById('tiffin-users');
        if (tiffinUsers) {
            tiffinUsers.innerHTML = '';
            
            activeUsers.forEach(user => {
                const option = document.createElement('option');
                option.value = user.user_id;
                option.textContent = `${user.name} (${user.user_id})`;
                tiffinUsers.appendChild(option);
            });
        }
        
        // Populate user select for batch tiffin
        const userGroupSelects = document.querySelectorAll('.user-group-select-input');
        userGroupSelects.forEach(select => {
            select.innerHTML = '';
            
                        activeUsers.forEach(user => {
                const option = document.createElement('option');
                option.value = user.user_id;
                option.textContent = `${user.name} (${user.user_id})`;
                select.appendChild(option);
            });
        });
        
    } catch (error) {
        console.error('Error loading users for select:', error);
        showNotification('Failed to load users for dropdown: ' + error.message, 'error');
    }
}

async function loadExistingTiffins(filters = {}) {
    try {
        console.log("Loading existing tiffins with filters:", filters);
        
        // Build query parameters
        const queryParams = [];
        if (filters.date) queryParams.push(`date=${filters.date}`);
        if (filters.status) queryParams.push(`status=${filters.status}`);
        if (filters.time) queryParams.push(`time=${filters.time}`);
        if (filters.user_id) queryParams.push(`user_id=${filters.user_id}`);
        
        const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';
        
        const response = await apiRequest(`/admin/tiffins${queryString}`);
        
        console.log("Existing tiffins response:", response);
        
        // The API now returns data in a paginated format
        const tiffins = response.data || [];
        console.log(`Loaded ${tiffins.length} existing tiffins`);
        
        const tiffinsList = document.getElementById('manage-tiffins-list');
        
        if (tiffins.length === 0) {
            tiffinsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No tiffins">
                    <p>No tiffins found</p>
                </div>
            `;
            return;
        }
        
        let tiffinsHTML = '';
        
        tiffins.forEach(tiffin => {
            const statusClass = `status-${tiffin.status}`;
            const assignedUsers = tiffin.assigned_users.length;
            
            tiffinsHTML += `
                <div class="tiffin-card" data-tiffin-id="${tiffin._id}">
                    <div class="tiffin-header">
                        <span class="tiffin-time">${formatTiffinTime(tiffin.time)}</span>
                        <span class="tiffin-status ${statusClass}">${formatTiffinStatus(tiffin.status)}</span>
                    </div>
                    <div class="tiffin-body">
                        <div class="tiffin-date">${formatDate(tiffin.date)}</div>
                        <div class="tiffin-description">${tiffin.description || 'No description'}</div>
                        <div class="tiffin-meta">
                            <span class="tiffin-users">Users: ${assignedUsers}</span>
                            <span class="tiffin-price">₹${tiffin.price.toFixed(2)}</span>
                        </div>
                        <button class="action-button manage-tiffin-btn">Manage</button>
                    </div>
                </div>
            `;
        });
        
        tiffinsList.innerHTML = tiffinsHTML;
        
        // Add event listeners to manage buttons
        document.querySelectorAll('.manage-tiffin-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const tiffinId = e.target.closest('.tiffin-card').dataset.tiffinId;
                showTiffinDetails(tiffinId);
            });
        });
        
    } catch (error) {
        console.error('Error loading existing tiffins:', error);
        document.getElementById('manage-tiffins-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading tiffins: ${error.message}</p>
            </div>
        `;
    }
}

function addUserGroup() {
    const container = document.getElementById('user-groups-container');
    if (!container) {
        console.error('User groups container not found');
        return;
    }
    
    const addGroupBtn = document.getElementById('add-user-group');
    if (!addGroupBtn) {
        console.error('Add group button not found');
        return;
    }
    
    const groupCount = container.querySelectorAll('.user-group').length + 1;
    
    const groupDiv = document.createElement('div');
    groupDiv.className = 'user-group';
    groupDiv.innerHTML = `
        <h4>Group ${groupCount}</h4>
        <div class="user-group-select">
            <select class="user-group-select-input" multiple>
                <!-- Users will be loaded here -->
            </select>
        </div>
        <button type="button" class="secondary-button remove-group-btn">Remove Group</button>
    `;
    
    // Insert before the "Add Another Group" button
    container.insertBefore(groupDiv, addGroupBtn);
    
    // Add event listener to remove button
    const removeBtn = groupDiv.querySelector('.remove-group-btn');
    if (removeBtn) {
        removeBtn.addEventListener('click', () => {
            container.removeChild(groupDiv);
            
            // Update group numbers
            container.querySelectorAll('.user-group').forEach((group, index) => {
                const groupHeading = group.querySelector('h4');
                if (groupHeading) {
                    groupHeading.textContent = `Group ${index + 1}`;
                }
            });
        });
    }
    
    // Populate user select
    const select = groupDiv.querySelector('.user-group-select-input');
    if (!select) {
        console.error('User group select not found in new group');
        return;
    }
    
    // Fetch users for this select
    fetch(`${API_BASE_URL}/admin/users`, {
        headers: {
            'X-API-Key': apiKey
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Failed to fetch users: ${response.status}`);
        }
        return response.json();
    })
    .then(users => {
        // Filter active users and sort by name
        const activeUsers = users
            .filter(user => user.active)
            .sort((a, b) => a.name.localeCompare(b.name));
        
        // Populate select with users
        activeUsers.forEach(user => {
            const option = document.createElement('option');
            option.value = user.user_id;
            option.textContent = `${user.name} (${user.user_id})`;
            select.appendChild(option);
        });
    })
    .catch(error => {
        console.error('Error loading users for group:', error);
        showNotification('Failed to load users for group', 'error');
    });
}

function resetUserGroups() {
    const container = document.getElementById('user-groups-container');
    if (container) {
        container.innerHTML = `
            <div class="user-group">
                <h4>Group 1</h4>
                <div class="user-group-select">
                    <select class="user-group-select-input" multiple>
                        <!-- Users will be loaded here -->
                    </select>
                </div>
            </div>
            <button id="add-user-group" class="secondary-button">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16">
                    <path fill="none" d="M0 0h24v24H0z"/>
                    <path d="M11 11V5h2v6h6v2h-6v6h-2v-6H5v-2z"/>
                </svg>
                Add Another Group
            </button>
        `;
        
        // Reload users for select
        loadUsersForSelect();
        
        // Setup event listener for add group button
        const addGroupBtn = document.getElementById('add-user-group');
        if (addGroupBtn) {
            addGroupBtn.addEventListener('click', addUserGroup);
        }
    }
}

async function showApproveRequestModal(requestId) {
    try {
        console.log(`Loading request details for approval: ${requestId}`);
        
        const request = await apiRequest(`/admin/tiffin-requests/${requestId}`);
        console.log("Request details loaded:", request);
        
        // Create a modal dynamically
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.id = 'approve-request-modal';
        
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Approve Special Request</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>Request from: ${request.user_id}</label>
                        <p>${request.description}</p>
                    </div>
                    <div class="form-group">
                        <label for="approve-date">Date</label>
                        <input type="date" id="approve-date" value="${request.preferred_date}" required>
                    </div>
                    <div class="form-group">
                        <label for="approve-time">Time Slot</label>
                        <select id="approve-time" required>
                            <option value="morning" ${request.preferred_time === 'morning' ? 'selected' : ''}>Morning</option>
                            <option value="evening" ${request.preferred_time === 'evening' ? 'selected' : ''}>Evening</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="approve-price">Price (₹)</label>
                        <input type="number" id="approve-price" min="0" step="0.01" value="150" required>
                    </div>
                    <div class="form-group">
                        <label for="approve-cancellation">Cancellation Time</label>
                        <input type="time" id="approve-cancellation" value="08:00" required>
                    </div>
                    <button id="submit-approval" class="action-button">Approve Request</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Close button event
        modal.querySelector('.close-modal').addEventListener('click', () => {
            document.body.removeChild(modal);
        });
        
        // Submit approval button
        modal.querySelector('#submit-approval').addEventListener('click', async () => {
            const date = modal.querySelector('#approve-date').value;
            const time = modal.querySelector('#approve-time').value;
            const price = parseFloat(modal.querySelector('#approve-price').value);
            const cancellationTime = modal.querySelector('#approve-cancellation').value;
            
            if (!date || !time || isNaN(price) || !cancellationTime) {
                showNotification('Please fill in all fields', 'error');
                return;
            }
            
            try {
                await apiRequest(`/admin/tiffin-requests/${requestId}/approve`, {
                    method: 'POST',
                    body: JSON.stringify({
                        date,
                        time,
                        price,
                        cancellation_time: cancellationTime
                    })
                });
                
                showNotification('Request approved successfully', 'success');
                document.body.removeChild(modal);
                
                // Reload pending requests
                loadPendingRequests();
                
            } catch (error) {
                console.error('Error approving request:', error);
                showNotification(error.message, 'error');
            }
        });
        
    } catch (error) {
        console.error('Error showing approve request modal:', error);
        showNotification(error.message, 'error');
    }
}

async function rejectRequest(requestId) {
    showConfirmDialog(
        'Reject Request',
        'Are you sure you want to reject this request?',
        async () => {
            try {
                await apiRequest(`/admin/tiffin-requests/${requestId}/reject`, {
                    method: 'POST'
                });
                
                showNotification('Request rejected successfully', 'success');
                
                // Reload pending requests
                loadPendingRequests();
                
            } catch (error) {
                console.error('Error rejecting request:', error);
                showNotification(error.message, 'error');
            }
        }
    );
}

// ================================================
// NOTICES & POLLS FUNCTIONS (ADMIN)
// ================================================

async function loadNoticesPolls() {
    if (userRole !== 'admin') return;
    
    console.log("Loading notices and polls admin page");
    
    // Load notices and polls
    loadAdminNotices();
    loadAdminPolls();
}

async function loadAdminNotices() {
    try {
        console.log("Loading admin notices with API key:", apiKey ? "Present" : "Missing");
        
        const notices = await apiRequest('/admin/notices');
        
        console.log(`Loaded ${notices.length} notices`);
        
        const noticesList = document.getElementById('admin-notices-list');
        
        if (notices.length === 0) {
            noticesList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No notices">
                    <p>No notices found</p>
                </div>
            `;
            return;
        }
        
        // Sort by creation date (newest first)
        notices.sort((a, b) => {
            const dateA = new Date(a.created_at);
            const dateB = new Date(b.created_at);
            return dateB - dateA;
        });
        
        let noticesHTML = '';
        
        notices.forEach(notice => {
            const priorityClass = notice.priority === 0 ? 'normal' : notice.priority === 1 ? 'important' : 'urgent';
            const priorityText = notice.priority === 0 ? 'Normal' : notice.priority === 1 ? 'Important' : 'Urgent';
            
            // Format expiration date if it exists
            let expiresText = '';
            if (notice.expires_at) {
                expiresText = `<span class="notice-expires">Expires: ${formatDate(notice.expires_at)}</span>`;
            }
            
            noticesHTML += `
                <div class="notice-card" data-notice-id="${notice._id}">
                    <div class="notice-card-header">
                        <span class="notice-card-title">${notice.title}</span>
                        <span class="notice-priority ${priorityClass}">${priorityText}</span>
                    </div>
                    <div class="notice-card-body">
                        <div class="notice-card-content">${notice.content}</div>
                        <div class="notice-card-footer">
                            <span>Created: ${formatDate(notice.created_at)}</span>
                            ${expiresText}
                            <button class="warning-button delete-notice-btn">Delete</button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        noticesList.innerHTML = noticesHTML;
        
        // Add event listeners to delete buttons
        document.querySelectorAll('.delete-notice-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const noticeId = e.target.closest('.notice-card').dataset.noticeId;
                deleteNotice(noticeId);
            });
        });
        
    } catch (error) {
        console.error('Error loading admin notices:', error);
        document.getElementById('admin-notices-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading notices: ${error.message}</p>
            </div>
        `;
    }
}

async function deleteNotice(noticeId) {
    showConfirmDialog(
        'Delete Notice',
        'Are you sure you want to delete this notice? This action cannot be undone.',
        async () => {
            try {
                console.log(`Deleting notice: ${noticeId}`);
                
                await apiRequest(`/admin/notices/${noticeId}`, {
                    method: 'DELETE'
                });
                
                showNotification('Notice deleted successfully', 'success');
                
                // Reload notices
                loadAdminNotices();
                
            } catch (error) {
                console.error('Error deleting notice:', error);
                showNotification('Failed to delete notice: ' + error.message, 'error');
            }
        }
    );
}

async function createNotice() {
    try {
        const title = document.getElementById('notice-title').value.trim();
        const content = document.getElementById('notice-content').value.trim();
        const priority = parseInt(document.getElementById('notice-priority').value);
        const expiresAt = document.getElementById('notice-expires').value;
        
        if (!title || !content) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }
        
        const notice = {
            title,
            content,
            priority
        };
        
        if (expiresAt) {
            notice.expires_at = new Date(expiresAt).toISOString();
        }
        
        const response = await fetch(`${API_BASE_URL}/admin/notices`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(notice)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create notice');
        }
        
        showNotification('Notice created successfully', 'success');
        document.getElementById('create-notice-modal').classList.remove('active');
        
        // Clear form
        document.getElementById('notice-title').value = '';
        document.getElementById('notice-content').value = '';
        document.getElementById('notice-priority').value = '0';
        document.getElementById('notice-expires').value = '';
        
        // Reload notices
        loadAdminNotices();
        
    } catch (error) {
        console.error('Error creating notice:', error);
        showNotification(error.message, 'error');
    }
}

async function loadAdminPolls() {
    try {
        console.log("Loading admin polls with API key:", apiKey ? "Present" : "Missing");
        
        // Get all polls including inactive ones
        const polls = await apiRequest('/admin/polls');
        
        console.log(`Loaded ${polls.length} admin polls`);
        
        const pollsList = document.getElementById('admin-polls-list');
        
        if (polls.length === 0) {
            pollsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No polls">
                    <p>No active polls found</p>
                </div>
            `;
            return;
        }
        
        // Sort by end date (soonest first)
        polls.sort((a, b) => {
            const dateA = new Date(a.end_date);
            const dateB = new Date(b.end_date);
            return dateA - dateB;
        });
        
        let pollsHTML = '';
        
        for (const poll of polls) {
            let optionsHTML = '';
            
            // Fetch votes for this poll to show detailed voting info
            let voteDetails = [];
            try {
                const votesResponse = await apiRequest(`/admin/polls/${poll._id}/votes`);
                voteDetails = votesResponse.votes || [];
            } catch (error) {
                console.error('Error fetching poll votes:', error);
                voteDetails = [];
            }
            
            poll.options.forEach((option, index) => {
                const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);
                const percentage = totalVotes > 0 ? Math.round((option.votes / totalVotes) * 100) : 0;
                
                // Get users who voted for this option
                const votersForOption = voteDetails
                    .filter(vote => vote.option_index === index)
                    .map(vote => vote.user_name || vote.user_id);
                
                let votersHTML = '';
                if (votersForOption.length > 0) {
                    votersHTML = `
                        <div class="poll-voters-section">
                            <button class="toggle-voters-btn" data-poll-id="${poll._id}" data-option-index="${index}">
                                Show ${votersForOption.length} voters
                            </button>
                            <div class="voters-list hidden" id="voters-list-${poll._id}-${index}">
                                <ul>
                                    ${votersForOption.map(voter => `<li>${voter}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    `;
                } else {
                    votersHTML = '<div class="no-voters">No votes yet</div>';
                }
                
                optionsHTML += `
                    <div class="poll-option">
                        <span class="poll-option-label">${option.option}</span>
                        <div class="poll-option-progress">
                            <div class="poll-option-bar" style="width: ${percentage}%"></div>
                        </div>
                        <span class="poll-option-percentage">${percentage}% (${option.votes} votes)</span>
                        ${votersHTML}
                    </div>
                `;
            });
            
            // Determine poll status
            const now = new Date();
            const startDate = new Date(poll.start_date);
            const endDate = new Date(poll.end_date);
            
            let statusClass = 'inactive';
            let statusText = 'Inactive';
            
            if (poll.active) {
                if (now < startDate) {
                    statusClass = 'pending';
                    statusText = 'Pending';
                } else if (now <= endDate) {
                    statusClass = 'active';
                    statusText = 'Active';
                } else {
                    statusClass = 'ended';
                    statusText = 'Ended';
                }
            }
            
            pollsHTML += `
                <div class="poll-card" data-poll-id="${poll._id}">
                    <div class="poll-card-header">
                        <span class="poll-card-title">${poll.question}</span>
                        <span class="poll-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="poll-card-body">
                        <div class="poll-options">
                            ${optionsHTML}
                        </div>
                        <div class="poll-card-footer">
                            <span>Start: ${formatDate(poll.start_date)}</span>
                            <span>End: ${formatDate(poll.end_date)}</span>
                            <button class="warning-button delete-poll-btn">Delete</button>
                        </div>
                    </div>
                </div>
            `;
        }
        
        pollsList.innerHTML = pollsHTML;
        
        // Add event listeners to delete buttons
        document.querySelectorAll('.delete-poll-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const pollId = e.target.closest('.poll-card').dataset.pollId;
                deletePoll(pollId);
            });
        });
        
        // Add event listeners for the toggle voters buttons
        document.querySelectorAll('.toggle-voters-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const pollId = e.target.dataset.pollId;
                const optionIndex = e.target.dataset.optionIndex;
                const votersList = document.getElementById(`voters-list-${pollId}-${optionIndex}`);
                
                if (votersList.classList.contains('hidden')) {
                    votersList.classList.remove('hidden');
                    e.target.textContent = 'Hide voters';
                } else {
                    votersList.classList.add('hidden');
                    const votersCount = votersList.querySelectorAll('li').length;
                    e.target.textContent = `Show ${votersCount} voters`;
                }
            });
        });
        
    } catch (error) {
        console.error('Error loading admin polls:', error);
        document.getElementById('admin-polls-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading polls: ${error.message}</p>
            </div>
        `;
    }
}

async function deletePoll(pollId) {
    showConfirmDialog(
        'Delete Poll',
        'Are you sure you want to delete this poll? This action cannot be undone.',
        async () => {
            try {
                console.log(`Deleting poll: ${pollId}`);
                
                await apiRequest(`/admin/polls/${pollId}`, {
                    method: 'DELETE'
                });
                
                showNotification('Poll deleted successfully', 'success');
                
                // Reload polls
                loadAdminPolls();
                
            } catch (error) {
                console.error('Error deleting poll:', error);
                showNotification('Failed to delete poll: ' + error.message, 'error');
            }
        }
    );
}

function addPollOption() {
    const optionsContainer = document.getElementById('poll-options-container');
    if (!optionsContainer) {
        console.error('Poll options container not found');
        return;
    }
    
    const optionCount = optionsContainer.querySelectorAll('.poll-option-item').length + 1;
    
    const optionDiv = document.createElement('div');
    optionDiv.className = 'poll-option-item';
    
    optionDiv.innerHTML = `
        <input type="text" class="poll-option form-control" placeholder="Option ${optionCount}">
        <button type="button" class="remove-option-btn">✕</button>
    `;
    
    optionsContainer.appendChild(optionDiv);
    
    // Add event listener to remove button
    const removeBtn = optionDiv.querySelector('.remove-option-btn');
    if (removeBtn) {
        removeBtn.addEventListener('click', function() {
            optionsContainer.removeChild(optionDiv);
        });
    }
    
    // Focus the new input
    const newInput = optionDiv.querySelector('.poll-option');
    if (newInput) {
        newInput.focus();
    }
}

function setupPollCreationModal() {
    // Clear existing options
    const optionsContainer = document.getElementById('poll-options-container');
    if (optionsContainer) {
        optionsContainer.innerHTML = '';
        
        // Add two default empty options
        addPollOption();
        addPollOption();
    }
    
    // Set default dates
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const startDateInput = document.getElementById('poll-start-date');
    const endDateInput = document.getElementById('poll-end-date');
    
    if (startDateInput) {
        startDateInput.value = today.toISOString().split('T')[0];
    }
    
    if (endDateInput) {
        endDateInput.value = tomorrow.toISOString().split('T')[0];
    }
    
    // Add event listener to add option button
    const addOptionBtn = document.getElementById('add-poll-option');
    if (addOptionBtn) {
        // Remove existing event listeners to prevent duplicates
        const newAddOptionBtn = addOptionBtn.cloneNode(true);
        if (addOptionBtn.parentNode) {
            addOptionBtn.parentNode.replaceChild(newAddOptionBtn, addOptionBtn);
        }
        
        newAddOptionBtn.addEventListener('click', addPollOption);
    }
    
    // Add event listener to submit button
    const submitPollBtn = document.getElementById('submit-poll');
    if (submitPollBtn) {
        // Remove existing event listeners to prevent duplicates
        const newSubmitPollBtn = submitPollBtn.cloneNode(true);
        if (submitPollBtn.parentNode) {
            submitPollBtn.parentNode.replaceChild(newSubmitPollBtn, submitPollBtn);
        }
        
        newSubmitPollBtn.addEventListener('click', createPoll);
    }
}

async function createPoll() {
    try {
        const question = document.getElementById('poll-question').value.trim();
        if (!question) {
            showNotification('Please enter a poll question', 'error');
            return;
        }
        
        // Get all option inputs
        const optionInputs = document.querySelectorAll('#poll-options-container .poll-option');
        
        if (!optionInputs || optionInputs.length < 2) {
            showNotification('Please add at least 2 options', 'error');
            return;
        }
        
        const options = [];
        for (let i = 0; i < optionInputs.length; i++) {
            const input = optionInputs[i];
            if (input && input.value) {
                const optionText = input.value.trim();
                if (optionText) {
                    options.push({
                        option: optionText,
                        votes: 0
                    });
                }
            }
        }
        
        if (options.length < 2) {
            showNotification('Please add at least 2 non-empty options', 'error');
            return;
        }
        
        const startDate = document.getElementById('poll-start-date').value;
        const endDate = document.getElementById('poll-end-date').value;
        
        if (!startDate || !endDate) {
            showNotification('Please select start and end dates', 'error');
            return;
        }
        
        // Format dates properly with timezone
        const start = new Date(startDate);
        start.setHours(0, 0, 0, 0);
        
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        
        const pollData = {
            question: question,
            options: options,
            start_date: start.toISOString(),
            end_date: end.toISOString(),
            active: true
        };
        
        console.log("Creating poll with data:", pollData);
        
        const result = await apiRequest('/admin/polls', {
            method: 'POST',
            body: JSON.stringify(pollData)
        });
        
        console.log("Poll creation result:", result);
        
        showNotification('Poll created successfully', 'success');
        document.getElementById('create-poll-modal').classList.remove('active');
        
        // Clear form
        document.getElementById('poll-question').value = '';
        document.getElementById('poll-start-date').value = '';
        document.getElementById('poll-end-date').value = '';
        
        // Clear options and add default ones
        const optionsContainer = document.getElementById('poll-options-container');
        if (optionsContainer) {
            optionsContainer.innerHTML = '';
            addPollOption();
            addPollOption();
        }
        
        // Reload admin polls
        loadAdminPolls();
        
    } catch (error) {
        console.error('Error creating poll:', error);
        showNotification('Failed to create poll: ' + error.message, 'error');
    }
}

// ================================================
// INVOICE MANAGEMENT FUNCTIONS (ADMIN)
// ================================================

async function loadGenerateInvoices() {
    if (userRole !== 'admin') return;
    
    console.log("Loading generate invoices page");
    
    // Set default dates (current month)
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().split('T')[0];
    
    document.getElementById('invoice-start-date').value = firstDay;
    document.getElementById('invoice-end-date').value = lastDay;
    
    // Load existing invoices
    await loadAdminInvoices();
    
    // Set up event listener for generate button
    const generateBtn = document.getElementById('generate-invoices-btn');
    if (generateBtn) {
        // Remove existing listeners
        const newGenerateBtn = generateBtn.cloneNode(true);
        if (generateBtn.parentNode) {
            generateBtn.parentNode.replaceChild(newGenerateBtn, generateBtn);
        }
        
        // Add new listener
        newGenerateBtn.addEventListener('click', generateInvoices);
    }
}

async function loadAdminInvoices(filters = {}) {
    try {
        console.log("Loading admin invoices with filters:", filters);
        
        // Show loading state
        const invoicesList = document.getElementById('admin-invoices-list');
        if (invoicesList) {
            invoicesList.innerHTML = `
                <div class="loading-state">
                    <span class="spinner"></span>
                    <p>Loading invoices...</p>
                </div>
            `;
        }
        
        // Build query parameters
        const queryParams = [];
        if (filters.user_id) queryParams.push(`user_id=${encodeURIComponent(filters.user_id)}`);
        if (filters.paid !== undefined) queryParams.push(`paid=${filters.paid}`);
        if (filters.start_date) queryParams.push(`start_date=${encodeURIComponent(filters.start_date)}`);
                if (filters.end_date) queryParams.push(`end_date=${encodeURIComponent(filters.end_date)}`);
        
        const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';
        
        // Make the actual API request
        const response = await fetch(`${API_BASE_URL}/admin/invoices${queryString}`, {
            method: 'GET',
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to load invoices');
        }
        
        const invoices = await response.json();
        console.log("Admin invoices loaded:", invoices);
        
        if (!invoicesList) {
            console.error("Admin invoices list element not found");
            return;
        }
        
        if (!invoices || invoices.length === 0) {
            invoicesList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No invoices">
                    <p>No invoices found</p>
                </div>
            `;
            return;
        }
        
        // Sort by date (newest first)
        invoices.sort((a, b) => {
            const dateA = new Date(a.generated_at || a.created_at || 0);
            const dateB = new Date(b.generated_at || b.created_at || 0);
            return dateB - dateA;
        });
        
        let invoicesHTML = '';
        
        invoices.forEach(invoice => {
            const statusClass = invoice.paid ? 'paid' : 'unpaid';
            const statusText = invoice.paid ? 'Paid' : 'Unpaid';
            const userName = invoice.user_details ? invoice.user_details.name : invoice.user_id;
            
            invoicesHTML += `
                <div class="invoice-card" data-invoice-id="${invoice._id}">
                    <div class="invoice-card-header">
                        <span>Invoice #${invoice._id.substring(0, 8)}</span>
                        <span class="invoice-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="invoice-card-body">
                        <div class="invoice-card-user">
                            <strong>User:</strong> ${userName}
                        </div>
                        <div class="invoice-card-dates">
                            <div class="invoice-card-date">
                                From
                                <span>${formatDate(invoice.start_date)}</span>
                            </div>
                            <div class="invoice-card-date">
                                To
                                <span>${formatDate(invoice.end_date)}</span>
                            </div>
                        </div>
                        <div class="invoice-card-tiffins">
                            <div class="invoice-card-tiffins-title">Total Tiffins</div>
                            <div class="invoice-card-tiffin-count">${invoice.tiffins ? invoice.tiffins.length : 0}</div>
                        </div>
                        <div class="invoice-card-total">
                            <span>Total Amount</span>
                            <span class="invoice-card-amount">₹${invoice.total_amount.toFixed(2)}</span>
                        </div>
                        ${!invoice.paid ? `
                        <button class="action-button mark-paid-btn" data-invoice-id="${invoice._id}">
                            Mark as Paid
                        </button>
                        ` : ''}
                    </div>
                </div>
            `;
        });
        
        invoicesList.innerHTML = invoicesHTML;
        
        // Add event listeners to mark paid buttons
        document.querySelectorAll('.mark-paid-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const invoiceId = e.target.dataset.invoiceId;
                markInvoicePaid(invoiceId);
            });
        });
        
    } catch (error) {
        console.error('Error loading admin invoices:', error);
        const invoicesList = document.getElementById('admin-invoices-list');
        if (invoicesList) {
            invoicesList.innerHTML = `
                <div class="empty-state">
                    <p>Error loading invoices: ${error.message}</p>
                </div>
            `;
        }
    }
}

async function generateInvoices() {
    try {
        const startDate = document.getElementById('invoice-start-date').value;
        const endDate = document.getElementById('invoice-end-date').value;
        
        if (!startDate || !endDate) {
            showNotification('Please select start and end dates', 'error');
            return;
        }
        
        if (new Date(startDate) > new Date(endDate)) {
            showNotification('Start date must be before end date', 'error');
            return;
        }
        
        showNotification('Generating invoices...', 'info');
        
        // Show loading state
        const generateBtn = document.getElementById('generate-invoices-btn');
        if (generateBtn) {
            generateBtn.disabled = true;
            generateBtn.innerHTML = '<span class="spinner"></span> Generating...';
        }
        
        // Make direct fetch call to ensure we're not using any cached data
        const response = await fetch(`${API_BASE_URL}/admin/generate-invoices?start_date=${encodeURIComponent(startDate)}&end_date=${encodeURIComponent(endDate)}`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to generate invoices');
        }
        
        const result = await response.json();
        console.log("Invoice generation result:", result);
        
        showNotification(`Successfully generated ${result.generated_invoices} invoices`, 'success');
        
        // Reset button state
        if (generateBtn) {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate Invoices';
        }
        
        // Reload invoices after a short delay to ensure they're available in the API
        setTimeout(() => {
            loadAdminInvoices();
        }, 1500); // Slightly longer delay
        
    } catch (error) {
        console.error('Error generating invoices:', error);
        showNotification('Failed to generate invoices: ' + error.message, 'error');
        
        // Reset button state
        const generateBtn = document.getElementById('generate-invoices-btn');
        if (generateBtn) {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate Invoices';
        }
    }
}

async function markInvoicePaid(invoiceId) {
    if (!invoiceId) {
        showNotification('Invalid invoice ID', 'error');
        return;
    }
    
    showConfirmDialog(
        'Mark Invoice as Paid',
        'Are you sure you want to mark this invoice as paid?',
        async () => {
            try {
                console.log(`Marking invoice as paid: ${invoiceId}`);
                
                const result = await apiRequest(`/admin/invoices/${invoiceId}/mark-paid`, {
                    method: 'PUT'
                });
                
                console.log("Mark as paid result:", result);
                
                showNotification('Invoice marked as paid successfully', 'success');
                
                // Reload invoices
                loadAdminInvoices();
                
            } catch (error) {
                console.error('Error marking invoice as paid:', error);
                showNotification('Failed to mark invoice as paid: ' + error.message, 'error');
            }
        }
    );
}

// ================================================
// SPECIAL REQUEST FUNCTIONS
// ================================================

async function submitTiffinRequest() {
    try {
        const description = document.getElementById('request-description').value.trim();
        const preferredDate = document.getElementById('request-date').value;
        const preferredTime = document.getElementById('request-time').value;
        const specialInstructions = document.getElementById('request-instructions').value.trim();
        
        if (!description || !preferredDate || !preferredTime) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }
        
        console.log("Submitting tiffin request with data:", {
            description,
            preferred_date: preferredDate,
            preferred_time: preferredTime,
            special_instructions: specialInstructions || null
        });
        
        const result = await apiRequest('/user/request-tiffin', {
            method: 'POST',
            body: JSON.stringify({
                description: description,
                preferred_date: preferredDate,
                preferred_time: preferredTime,
                special_instructions: specialInstructions || null
            })
        });
        
        console.log("Tiffin request result:", result);
        
        showNotification('Request submitted successfully', 'success');
        document.getElementById('request-tiffin-modal').classList.remove('active');
        
        // Clear form
        document.getElementById('request-description').value = '';
        document.getElementById('request-date').value = '';
        document.getElementById('request-time').value = '';
        document.getElementById('request-instructions').value = '';
        
    } catch (error) {
        console.error('Error submitting tiffin request:', error);
        showNotification('Failed to submit request: ' + error.message, 'error');
    }
}

// ================================================
// UTILITY FUNCTIONS
// ================================================

function createPlaceholderSVG(text) {
    return `data:image/svg+xml;charset=UTF-8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect width="100%" height="100%" fill="%23f5f5f5"/><text x="50%" y="50%" font-family="Arial" font-size="14" text-anchor="middle" dominant-baseline="middle" fill="%23aaa">${text}</text></svg>`;
}

function getInitials(name) {
    if (!name) return '';
    return name
        .split(' ')
        .map(part => part.charAt(0))
        .join('')
        .toUpperCase()
        .substring(0, 2);
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    try {
        const date = new Date(dateString);
        if (isNaN(date.getTime())) {
            return dateString;
        }
        
        const options = { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' };
        return date.toLocaleDateString(undefined, options);
    } catch (error) {
        console.error('Error formatting date:', error);
        return dateString || 'N/A';
    }
}

function formatTime(timeStr) {
    if (!timeStr) return 'N/A';
    
    try {
        const [hours, minutes] = timeStr.split(':');
        const hour = parseInt(hours);
        const ampm = hour >= 12 ? 'PM' : 'AM';
        const formattedHour = hour % 12 || 12;
        return `${formattedHour}:${minutes} ${ampm}`;
    } catch (error) {
        console.error('Error formatting time:', error);
        return timeStr || 'N/A';
    }
}

function formatTiffinTime(timeStr) {
    if (!timeStr) return 'N/A';
    
    const timeMap = {
        'morning': 'Morning',
        'evening': 'Evening'
    };
    
    return timeMap[timeStr] || timeStr;
}

function formatTiffinStatus(status) {
    if (!status) return 'Unknown';
    
    const statusMap = {
        'scheduled': 'Scheduled',
        'preparing': 'Preparing',
        'prepared': 'Prepared',
        'out_for_delivery': 'Out for Delivery',
        'delivered': 'Delivered',
        'cancelled': 'Cancelled'
    };
    
    return statusMap[status] || status;
}

function showNotification(message, type = 'info') {
    const toast = document.getElementById('notification-toast');
    const toastMessage = document.getElementById('notification-toast-message');
    
    toastMessage.textContent = message;
    
    // Set color based on type
    switch (type) {
        case 'success':
            toast.style.backgroundColor = 'var(--success)';
            break;
        case 'error':
            toast.style.backgroundColor = 'var(--danger)';
            break;
        case 'warning':
            toast.style.backgroundColor = 'var(--warning)';
            break;
        default:
            toast.style.backgroundColor = 'var(--info)';
    }
    
    toast.classList.add('active');
    
    // Hide after 3 seconds
    setTimeout(() => {
        toast.classList.remove('active');
    }, 3000);
}

function showConfirmDialog(title, message, onConfirm) {
    const modal = document.getElementById('confirm-modal');
    const titleEl = document.getElementById('confirm-title');
    const messageEl = document.getElementById('confirm-message');
    const yesBtn = document.getElementById('confirm-yes');
    const noBtn = document.getElementById('confirm-no');
    
    titleEl.textContent = title;
    messageEl.textContent = message;
    
    // Show modal
    modal.classList.add('active');
    
    // Setup buttons
    const closeModal = () => {
        modal.classList.remove('active');
    };
    
    // Remove existing listeners to prevent duplicates
    const newYesBtn = yesBtn.cloneNode(true);
    yesBtn.parentNode.replaceChild(newYesBtn, yesBtn);
    
    const newNoBtn = noBtn.cloneNode(true);
    noBtn.parentNode.replaceChild(newNoBtn, noBtn);
    
    const newCloseBtn = modal.querySelector('.close-modal').cloneNode(true);
    modal.querySelector('.close-modal').parentNode.replaceChild(
        newCloseBtn, 
        modal.querySelector('.close-modal')
    );
    
    // Add new listeners
    newYesBtn.addEventListener('click', () => {
        closeModal();
        onConfirm();
    });
    
    newNoBtn.addEventListener('click', closeModal);
    newCloseBtn.addEventListener('click', closeModal);
}

function initializeTheme() {
    const savedTheme = localStorage.getItem('tiffinTreatsTheme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
        document.querySelector('.theme-light').classList.add('hidden');
        document.querySelector('.theme-dark').classList.remove('hidden');
    } else {
        document.body.classList.remove('dark-theme');
        document.querySelector('.theme-light').classList.remove('hidden');
        document.querySelector('.theme-dark').classList.add('hidden');
    }
}

function toggleTheme() {
    const isDark = document.body.classList.contains('dark-theme');
    
    if (isDark) {
        document.body.classList.remove('dark-theme');
        document.querySelector('.theme-light').classList.remove('hidden');
        document.querySelector('.theme-dark').classList.add('hidden');
        localStorage.setItem('tiffinTreatsTheme', 'light');
    } else {
        document.body.classList.add('dark-theme');
        document.querySelector('.theme-light').classList.add('hidden');
        document.querySelector('.theme-dark').classList.remove('hidden');
                localStorage.setItem('tiffinTreatsTheme', 'dark');
    }
}

// ================================================
// EVENT LISTENERS SETUP
// ================================================

function setupEventListeners() {
    // Auth tabs
    document.getElementById('login-tab').addEventListener('click', () => {
        document.getElementById('login-tab').classList.add('active');
        document.getElementById('register-tab').classList.remove('active');
        document.getElementById('login-form').classList.remove('hidden');
        document.getElementById('register-form').classList.add('hidden');
    });
    
    document.getElementById('register-tab').addEventListener('click', () => {
        document.getElementById('register-tab').classList.add('active');
        document.getElementById('login-tab').classList.remove('active');
        document.getElementById('register-form').classList.remove('hidden');
        document.getElementById('login-form').classList.add('hidden');
    });

    // Notices & Polls tabs
    document.querySelector('#notices-polls-tabs .tab-btn[data-tab="notices"]').addEventListener('click', function() {
        document.querySelectorAll('#notices-polls-tabs .tab-btn').forEach(tab => {
            tab.classList.remove('active');
        });
        this.classList.add('active');
        
        document.querySelectorAll('#notices-polls-page .tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        
        document.getElementById('notices-tab').classList.add('active');
    });
    
    document.querySelector('#notices-polls-tabs .tab-btn[data-tab="polls"]').addEventListener('click', function() {
        document.querySelectorAll('#notices-polls-tabs .tab-btn').forEach(tab => {
            tab.classList.remove('active');
        });
        this.classList.add('active');
        
        document.querySelectorAll('#notices-polls-page .tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        
        document.getElementById('polls-tab').classList.add('active');
    });

    // Tiffin management tabs
    const tiffinTabBtns = document.querySelectorAll('.tiffin-management-tabs .tab-btn');
    tiffinTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            console.log('Tiffin tab clicked:', this.getAttribute('data-tab'));
            
            // Remove active class from all tabs
            document.querySelectorAll('.tiffin-management-tabs .tab-btn').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Add active class to clicked tab
            this.classList.add('active');
            
            // Hide all tab panes
            document.querySelectorAll('#manage-tiffins-page .tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            
            // Show selected tab pane
            const tabId = this.getAttribute('data-tab');
            const targetPane = document.getElementById(`${tabId}-tab`);
            if (targetPane) {
                targetPane.classList.add('active');
                console.log('Activating pane:', tabId);
            } else {
                console.error('Could not find tab pane:', tabId);
            }
        });
    });

    // Login form with loading indicator
    document.getElementById('login-btn').addEventListener('click', async () => {
        const userId = document.getElementById('login-userid').value.trim();
        const password = document.getElementById('login-password').value;
        
        if (!userId || !password) {
            document.getElementById('login-message').textContent = 'Please enter both user ID and password';
            return;
        }
        
        // Show loading indicator
        document.getElementById('login-btn').innerHTML = '<span class="spinner"></span> Logging in...';
        document.getElementById('login-btn').disabled = true;
        
        try {
            const success = await login(userId, password);
            if (!success) {
                document.getElementById('login-message').textContent = 'Invalid credentials. Please try again.';
            }
        } finally {
            // Reset button regardless of outcome
            document.getElementById('login-btn').innerHTML = 'Login';
            document.getElementById('login-btn').disabled = false;
        }
    });
    
    // Register form
    document.getElementById('register-btn').addEventListener('click', () => {
        document.getElementById('register-message').textContent = 'Registration is disabled. Please contact an administrator.';
    });
    
    // Logout button
    document.getElementById('logout-btn').addEventListener('click', logout);
    
    // Navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.id !== 'logout-btn') {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const pageId = link.dataset.page;
                if (pageId) {
                    navigateTo(pageId);
                }
            });
        }
    });
    
    // Toggle sidebar on mobile
    document.getElementById('toggle-sidebar').addEventListener('click', () => {
        document.querySelector('.sidebar').classList.toggle('active');
    });
    
    // Theme toggle
    document.getElementById('theme-toggle-btn').addEventListener('click', toggleTheme);
    
    // Profile form submit
    document.getElementById('save-profile').addEventListener('click', updateUserProfile);
    
    // Password change form submit
    document.getElementById('change-password').addEventListener('click', changePassword);
    
    // Tiffin filters
    document.getElementById('apply-tiffin-filter').addEventListener('click', () => {
        const date = document.getElementById('tiffin-date-filter').value;
        const time = document.getElementById('tiffin-time-filter').value;
        const status = document.getElementById('tiffin-status-filter').value;
        
        // Fetch all tiffins and filter client-side
        fetch(`${API_BASE_URL}/user/tiffins`, {
            headers: {
                'X-API-Key': apiKey
            }
        })
        .then(response => response.json())
        .then(data => {
            displayTiffins(data.data || data, { date, time, status });
        })
        .catch(error => {
            console.error('Error applying filters:', error);
            showNotification('Failed to apply filters', 'error');
        });
    });
    
    document.getElementById('reset-tiffin-filter').addEventListener('click', () => {
        document.getElementById('tiffin-date-filter').value = '';
        document.getElementById('tiffin-time-filter').value = '';
        document.getElementById('tiffin-status-filter').value = '';
        
        loadTiffins();
    });
    
    // History filters
    document.getElementById('apply-history-filter').addEventListener('click', () => {
        const startDate = document.getElementById('history-start-date').value;
        const endDate = document.getElementById('history-end-date').value;
        
        // Fetch all history and filter client-side
        fetch(`${API_BASE_URL}/user/history`, {
            headers: {
                'X-API-Key': apiKey
            }
        })
        .then(response => response.json())
        .then(data => {
            const history = data.data || data;
            displayHistory(history, { startDate, endDate });
            updateHistoryStats(history.filter(
                item => (!startDate || item.date >= startDate) && 
                       (!endDate || item.date <= endDate)
            ));
        })
        .catch(error => {
            console.error('Error applying filters:', error);
            showNotification('Failed to apply filters', 'error');
        });
    });
    
    document.getElementById('reset-history-filter').addEventListener('click', () => {
        document.getElementById('history-start-date').value = '';
        document.getElementById('history-end-date').value = '';
        
        loadHistory();
    });
    
    // Manage tiffins filters
    document.getElementById('apply-manage-filter').addEventListener('click', () => {
        const date = document.getElementById('manage-tiffin-date').value;
        const status = document.getElementById('manage-tiffin-status').value;
        
        loadExistingTiffins({ date, status });
    });
    
    document.getElementById('reset-manage-filter').addEventListener('click', () => {
        document.getElementById('manage-tiffin-date').value = '';
        document.getElementById('manage-tiffin-status').value = '';
        
        loadExistingTiffins();
    });
    
    // Create notice
    document.getElementById('add-notice-btn').addEventListener('click', () => {
        document.getElementById('create-notice-modal').classList.add('active');
    });
    
    document.querySelector('#create-notice-modal .close-modal').addEventListener('click', () => {
        document.getElementById('create-notice-modal').classList.remove('active');
    });
    
    document.getElementById('submit-notice').addEventListener('click', createNotice);
    
    // Create poll
    document.getElementById('add-poll-btn').addEventListener('click', function() {
        setupPollCreationModal();
        document.getElementById('create-poll-modal').classList.add('active');
    });
    
    document.querySelector('#create-poll-modal .close-modal').addEventListener('click', () => {
        document.getElementById('create-poll-modal').classList.remove('active');
    });
    
    document.getElementById('add-poll-option').addEventListener('click', addPollOption);
    document.getElementById('submit-poll').addEventListener('click', createPoll);
    
    // Generate invoices
    document.getElementById('generate-invoices-btn').addEventListener('click', generateInvoices);
    
    // User search
    document.getElementById('user-search').addEventListener('input', (e) => {
        const searchQuery = e.target.value.trim();
        
        // Fetch all users and filter client-side
        fetch(`${API_BASE_URL}/admin/users`, {
            headers: {
                'X-API-Key': apiKey
            }
        })
        .then(response => response.json())
        .then(users => {
            displayUsers(users, searchQuery);
        })
        .catch(error => {
            console.error('Error searching users:', error);
            showNotification('Failed to search users', 'error');
        });
    });
    
    // Add user
    document.getElementById('add-user-btn').addEventListener('click', () => {
        document.getElementById('add-user-modal').classList.add('active');
    });
    
    document.querySelector('#add-user-modal .close-modal').addEventListener('click', () => {
        document.getElementById('add-user-modal').classList.remove('active');
    });
    
    document.getElementById('submit-new-user').addEventListener('click', createUser);
    
    // Request special tiffin
    document.getElementById('request-tiffin-btn').addEventListener('click', () => {
        document.getElementById('request-tiffin-modal').classList.add('active');
    });
    
    document.querySelector('#request-tiffin-modal .close-modal').addEventListener('click', () => {
        document.getElementById('request-tiffin-modal').classList.remove('active');
    });
    
    document.getElementById('submit-request').addEventListener('click', submitTiffinRequest);
    
    // Create tiffin
    document.getElementById('create-tiffin-btn').addEventListener('click', createTiffinWithoutMenuItems);
    
    // Batch create tiffins
    document.getElementById('batch-create-btn').addEventListener('click', batchCreateTiffinsWithoutMenuItems);
    
    // Add user group for batch create
    document.getElementById('add-user-group').addEventListener('click', addUserGroup);
    
    // Notifications dropdown
    document.getElementById('notifications-btn').addEventListener('click', () => {
        document.getElementById('notification-dropdown').classList.toggle('active');
    });
    
    // Close notifications when clicking outside
    document.addEventListener('click', (e) => {
        const dropdown = document.getElementById('notification-dropdown');
        const btn = document.getElementById('notifications-btn');
        
        if (dropdown.classList.contains('active') && 
            !dropdown.contains(e.target) && 
            !btn.contains(e.target)) {
            dropdown.classList.remove('active');
        }
    });
    
    // Mark all notifications as read
    document.getElementById('mark-all-read').addEventListener('click', markAllNotificationsRead);
    
    // Setup quick action links
    document.querySelectorAll('.quick-action-card').forEach(card => {
        card.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = card.getAttribute('data-page');
            if (pageId) {
                navigateTo(pageId);
            }
        });
    });
    
    // Call our form setup functions
    setupCreateTiffinForm();
    setupBatchCreateTiffinForm();

}
 
