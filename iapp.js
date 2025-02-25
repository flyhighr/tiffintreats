// app.js - TiffinTreats Frontend JavaScript

// Global Variables
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
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error(`Error from ${endpoint}:`, errorData);
            throw new Error(errorData.detail || 'Request failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API request to ${endpoint} failed:`, error);
        throw error;
    }
}

// Authentication Functions
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
        
        const response = await fetch(`${API_BASE_URL}/auth/login?user_id=${userId}&password=${password}`);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Login failed');
        }
        
        const data = await response.json();
        
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
        
        // For regular users, fetch from API
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

function logout() {
    console.log("Logging out user");
    localStorage.removeItem('tiffinTreatsAuth');
    apiKey = null;
    userRole = null;
    currentUser = null;
    showLogin();
}
// UI State Functions
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

function updateUserInfo() {
    if (!currentUser) return;
    
    // Sidebar user info
    document.getElementById('user-name').textContent = currentUser.name;
    document.getElementById('user-role').textContent = userRole === 'admin' ? 'Administrator' : 'User';
    document.getElementById('user-initial').textContent = getInitials(currentUser.name);
    
    // Profile page
    document.getElementById('profile-name').textContent = currentUser.name;
    document.getElementById('profile-user-id').textContent = currentUser.user_id;
    document.getElementById('profile-initial').textContent = getInitials(currentUser.name);
    
    // Profile form fields
    document.getElementById('profile-edit-name').value = currentUser.name;
    document.getElementById('profile-edit-email').value = currentUser.email;
    document.getElementById('profile-edit-address').value = currentUser.address;
}

// Navigation Functions
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

// Dashboard Functions
// Dashboard Functions
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
                    <img src="empty-notices.svg" alt="No notices">
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

async function loadPolls() {
    try {
        console.log("Loading polls");
        
        const polls = await apiRequest('/user/polls');
        
        console.log(`Loaded ${polls.length} polls`);
        
        const pollsContainer = document.getElementById('polls-container');
        
        if (polls.length === 0) {
            pollsContainer.innerHTML = `
                <div class="empty-state">
                    <img src="empty-polls.svg" alt="No polls">
                    <p>No active polls at the moment</p>
                </div>
            `;
            return;
        }
        
        let pollsHTML = '';
        
        polls.forEach(poll => {
            let optionsHTML = '';
            
            poll.options.forEach((option, index) => {
                const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);
                const percentage = totalVotes > 0 ? Math.round((option.votes / totalVotes) * 100) : 0;
                
                optionsHTML += `
                    <div class="poll-option">
                        <span class="poll-option-label">${option.option}</span>
                        <div class="poll-option-progress">
                            <div class="poll-option-bar" style="width: ${percentage}%"></div>
                        </div>
                        <span class="poll-option-percentage">${percentage}%</span>
                    </div>
                `;
            });
            
            pollsHTML += `
                <div class="poll-item" data-poll-id="${poll._id}">
                    <div class="poll-question">${poll.question}</div>
                    <div class="poll-options">
                        ${optionsHTML}
                    </div>
                    <div class="poll-meta">
                        <span>Ends on ${formatDate(poll.end_date)}</span>
                        <button class="poll-vote-btn action-button" data-poll-id="${poll._id}">Vote</button>
                    </div>
                </div>
            `;
        });
        
        pollsContainer.innerHTML = pollsHTML;
        
        // Add event listeners to vote buttons
        document.querySelectorAll('.poll-vote-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const pollId = e.target.dataset.pollId;
                showVotePollModal(pollId);
            });
        });
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
        
        const today = new Date().toISOString().split('T')[0];
        const response = await fetch(`${API_BASE_URL}/user/tiffins?date=${today}`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Today's tiffin response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Today's tiffin error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load today\'s tiffin');
        }
        
        const tiffins = await response.json();
        console.log(`Loaded ${tiffins.length} tiffins for today`);
        
        const todayTiffinStatus = document.getElementById('today-tiffin-status');
        const nextDeliveryTime = document.getElementById('next-delivery-time');
        
        if (tiffins.length === 0) {
            todayTiffinStatus.textContent = 'No tiffin scheduled for today';
            nextDeliveryTime.textContent = 'N/A';
            return;
        }
        
        // Find the next tiffin based on current time
        const now = new Date();
        const currentHour = now.getHours();
        
        let nextTiffin = tiffins.find(tiffin => {
            const deliveryHour = parseInt(tiffin.delivery_time.split(':')[0]);
            return deliveryHour > currentHour;
        });
        
        // If no next tiffin found, use the first one
        if (!nextTiffin) {
            nextTiffin = tiffins[0];
        }
        
        // Update today's tiffin status
        todayTiffinStatus.textContent = formatTiffinStatus(nextTiffin.status);
        
        // Update next delivery time
        nextDeliveryTime.textContent = formatTime(nextTiffin.delivery_time);
    } catch (error) {
        console.error('Error loading today\'s tiffin:', error);
        document.getElementById('today-tiffin-status').textContent = 'Error loading status';
        document.getElementById('next-delivery-time').textContent = 'N/A';
    }
}

async function loadUpcomingTiffins() {
    try {
        console.log("Loading upcoming tiffins");
        
        const today = new Date().toISOString().split('T')[0];
        const response = await fetch(`${API_BASE_URL}/user/tiffins`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Upcoming tiffins response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Upcoming tiffins error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load upcoming tiffins');
        }
        
        const tiffins = await response.json();
        console.log(`Loaded ${tiffins.length} total tiffins`);
        
        const upcomingTiffins = document.getElementById('upcoming-tiffins');
        
        // Filter upcoming tiffins (today and future)
        const upcoming = tiffins.filter(tiffin => {
            const tiffinDate = new Date(tiffin.date);
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            return tiffinDate >= today && tiffin.status !== 'cancelled';
        });
        
        console.log(`Filtered to ${upcoming.length} upcoming tiffins`);
        
        // Sort by date and time
        upcoming.sort((a, b) => {
            const dateA = new Date(a.date);
            const dateB = new Date(b.date);
            if (dateA.getTime() !== dateB.getTime()) {
                return dateA - dateB;
            }
            return a.delivery_time.localeCompare(b.delivery_time);
        });
        
        // Limit to next 6 tiffins
        const nextTiffins = upcoming.slice(0, 6);
        
        if (nextTiffins.length === 0) {
            upcomingTiffins.innerHTML = `
                <div class="empty-state">
                    <img src="empty-tiffins.svg" alt="No upcoming tiffins">
                    <p>No upcoming tiffins scheduled</p>
                </div>
            `;
            return;
        }
        
        let tiffinsHTML = '';
        
        nextTiffins.forEach(tiffin => {
            const statusClass = `status-${tiffin.status}`;
            
            tiffinsHTML += `
                <div class="tiffin-card" data-tiffin-id="${tiffin._id}">
                    <div class="tiffin-header">
                        <span class="tiffin-time">${formatTiffinTime(tiffin.time)}</span>
                        <span class="tiffin-status ${statusClass}">${formatTiffinStatus(tiffin.status)}</span>
                    </div>
                    <div class="tiffin-body">
                        <div class="tiffin-date">${formatDate(tiffin.date)}</div>
                                                <div class="tiffin-description">${tiffin.description}</div>
                        <div class="tiffin-meta">
                            <span class="tiffin-delivery-time">Delivery at ${formatTime(tiffin.delivery_time)}</span>
                            <span class="tiffin-price">₹${tiffin.price.toFixed(2)}</span>
                        </div>
                    </div>
                </div>
            `;
        });
        
        upcomingTiffins.innerHTML = tiffinsHTML;
        
        // Add event listeners to tiffin cards
        document.querySelectorAll('.tiffin-card').forEach(card => {
            card.addEventListener('click', (e) => {
                const tiffinId = e.currentTarget.dataset.tiffinId;
                showTiffinDetails(tiffinId);
            });
        });
        
        // Update month tiffin count
        const currentMonth = new Date().getMonth();
        const currentYear = new Date().getFullYear();
        
        const monthTiffins = tiffins.filter(tiffin => {
            const tiffinDate = new Date(tiffin.date);
            return tiffinDate.getMonth() === currentMonth && 
                   tiffinDate.getFullYear() === currentYear &&
                   tiffin.status !== 'cancelled';
        });
        
        document.getElementById('month-tiffin-count').textContent = `${monthTiffins.length} tiffins`;
        
    } catch (error) {
        console.error('Error loading upcoming tiffins:', error);
        document.getElementById('upcoming-tiffins').innerHTML = `
            <div class="empty-state">
                <p>Error loading tiffins: ${error.message}</p>
            </div>
        `;
    }
}

// Tiffins Page Functions
async function loadTiffins() {
    try {
        console.log("Loading tiffins with API key:", apiKey ? "Present" : "Missing");
        
        const response = await fetch(`${API_BASE_URL}/user/tiffins`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Tiffins response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Tiffins error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load tiffins');
        }
        
        const tiffins = await response.json();
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
        return a.delivery_time.localeCompare(b.delivery_time);
    });
    
    if (filteredTiffins.length === 0) {
        tiffinsList.innerHTML = `
            <div class="empty-state">
                <img src="empty-tiffins.svg" alt="No tiffins">
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
                    <div class="tiffin-description">${tiffin.description}</div>
                    <div class="tiffin-meta">
                        <span class="tiffin-delivery-time">Delivery at ${formatTime(tiffin.delivery_time)}</span>
                        <span class="tiffin-price">₹${tiffin.price.toFixed(2)}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    tiffinsList.innerHTML = tiffinsHTML;
    
    // Add event listeners to tiffin cards
    document.querySelectorAll('.tiffin-card').forEach(card => {
        card.addEventListener('click', (e) => {
            const tiffinId = e.currentTarget.dataset.tiffinId;
            showTiffinDetails(tiffinId);
        });
    });
}

async function showTiffinDetails(tiffinId) {
    try {
        console.log(`Loading details for tiffin: ${tiffinId}`);
        
        // Fetch tiffin details
        const tiffin = await fetchTiffinDetails(tiffinId);
        
        // Populate modal
        document.getElementById('tiffin-details-status').textContent = formatTiffinStatus(tiffin.status);
        document.getElementById('tiffin-details-status').className = `status-badge status-${tiffin.status}`;
        
        document.getElementById('tiffin-details-date').textContent = formatDate(tiffin.date);
        document.getElementById('tiffin-details-time').textContent = formatTiffinTime(tiffin.time);
        document.getElementById('tiffin-details-description').textContent = tiffin.description;
        
        // Menu items
        const menuItemsList = document.getElementById('tiffin-details-menu-items');
        menuItemsList.innerHTML = '';
        
        tiffin.menu_items.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            menuItemsList.appendChild(li);
        });
        
        // Delivery info
        document.getElementById('tiffin-details-price').textContent = `₹${tiffin.price.toFixed(2)}`;
        document.getElementById('tiffin-details-delivery-time').textContent = formatTime(tiffin.delivery_time);
        document.getElementById('tiffin-details-cancellation-time').textContent = formatTime(tiffin.cancellation_time);
        
        // Show/hide appropriate action buttons
        const adminActions = document.querySelector('.tiffin-details-actions.admin-only');
        const userActions = document.querySelector('.tiffin-details-actions.user-only');
        
        if (userRole === 'admin') {
            adminActions.classList.remove('hidden');
            userActions.classList.add('hidden');
        } else {
            adminActions.classList.add('hidden');
            userActions.classList.remove('hidden');
            
            // Check if cancellation is allowed
            const cancelBtn = document.getElementById('cancel-tiffin-btn');
            const isCancellable = await checkTiffinCancellable(tiffin);
            
            if (isCancellable && tiffin.status !== 'cancelled') {
                cancelBtn.disabled = false;
                cancelBtn.classList.remove('hidden');
            } else {
                cancelBtn.disabled = true;
                cancelBtn.classList.add('hidden');
            }
        }
        
        // Show modal
        const modal = document.getElementById('tiffin-details-modal');
        modal.classList.add('active');
        
        // Setup event listeners
        setupTiffinDetailsListeners(tiffinId);
        
    } catch (error) {
        console.error('Error showing tiffin details:', error);
        showNotification('Failed to load tiffin details: ' + error.message, 'error');
    }
}

async function fetchTiffinDetails(tiffinId) {
    console.log(`Fetching details for tiffin ID: ${tiffinId}, user role: ${userRole}`);
    
    // For user role, we'll use the user/tiffins endpoint
    // For admin role, we'll use the admin/tiffins/{tiffin_id} endpoint
    
    let tiffin;
    
    if (userRole === 'admin') {
        const response = await fetch(`${API_BASE_URL}/admin/tiffins/${tiffinId}`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Tiffin details response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Tiffin details error:", errorData);
            throw new Error(errorData.detail || 'Failed to fetch tiffin details');
        }
        
        tiffin = await response.json();
    } else {
        // For users, we need to get all tiffins and find the right one
        const response = await fetch(`${API_BASE_URL}/user/tiffins`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("User tiffins response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("User tiffins error:", errorData);
            throw new Error(errorData.detail || 'Failed to fetch tiffin details');
        }
        
        const tiffins = await response.json();
        tiffin = tiffins.find(t => t._id === tiffinId);
        
        if (!tiffin) {
            throw new Error('Tiffin not found');
        }
    }
    
    console.log("Tiffin details loaded:", tiffin);
    return tiffin;
}


async function checkTiffinCancellable(tiffin) {
    // Check if current time is before cancellation time
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const tiffinDate = tiffin.date;
    
    // If tiffin date is in the past, not cancellable
    if (tiffinDate < today) {
        return false;
    }
    
    // If tiffin date is in the future, cancellable
    if (tiffinDate > today) {
        return true;
    }
    
    // If tiffin is today, check cancellation time
    const [hours, minutes] = tiffin.cancellation_time.split(':').map(Number);
    const cancellationTime = new Date();
    cancellationTime.setHours(hours, minutes, 0, 0);
    
    return now < cancellationTime;
}

function setupTiffinDetailsListeners(tiffinId) {
    // Close button
    document.querySelector('#tiffin-details-modal .close-modal').addEventListener('click', () => {
        document.getElementById('tiffin-details-modal').classList.remove('active');
    });
    
    // Cancel tiffin button (for users)
    const cancelBtn = document.getElementById('cancel-tiffin-btn');
    cancelBtn.onclick = () => {
        // Show confirmation dialog
        showConfirmDialog(
            'Cancel Tiffin',
            'Are you sure you want to cancel this tiffin? This action cannot be undone.',
            async () => {
                try {
                    const response = await fetch(`${API_BASE_URL}/user/cancel-tiffin?tiffin_id=${tiffinId}`, {
                        method: 'POST',
                        headers: {
                            'X-API-Key': apiKey
                        }
                    });
                    
                    if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.detail || 'Failed to cancel tiffin');
                    }
                    
                    showNotification('Tiffin cancelled successfully', 'success');
                    document.getElementById('tiffin-details-modal').classList.remove('active');
                    
                    // Reload tiffins
                    loadTiffins();
                    loadDashboard();
                } catch (error) {
                    console.error('Error cancelling tiffin:', error);
                    showNotification(error.message, 'error');
                }
            }
        );
    };
    
    // Update status button (for admins)
    const updateStatusBtn = document.getElementById('update-tiffin-status-btn');
    const statusDropdown = document.getElementById('status-dropdown');
    
    if (updateStatusBtn) {
        updateStatusBtn.onclick = (e) => {
            e.stopPropagation();
            statusDropdown.classList.toggle('active');
        };
        
        // Status options
        document.querySelectorAll('.status-option').forEach(option => {
            option.onclick = async (e) => {
                e.stopPropagation();
                const status = e.target.dataset.status;
                
                try {
                    const response = await fetch(`${API_BASE_URL}/admin/tiffins/${tiffinId}/status?status=${status}`, {
                        method: 'PUT',
                        headers: {
                            'X-API-Key': apiKey
                        }
                    });
                    
                                        if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.detail || 'Failed to update tiffin status');
                    }
                    
                    showNotification('Tiffin status updated successfully', 'success');
                    statusDropdown.classList.remove('active');
                    
                    // Update status in modal
                    document.getElementById('tiffin-details-status').textContent = formatTiffinStatus(status);
                    document.getElementById('tiffin-details-status').className = `status-badge status-${status}`;
                    
                    // Reload tiffins if on manage tiffins page
                    if (document.getElementById('manage-tiffins-page').classList.contains('active')) {
                        loadManageTiffins();
                    }
                } catch (error) {
                    console.error('Error updating tiffin status:', error);
                    showNotification(error.message, 'error');
                }
            };
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (statusDropdown.classList.contains('active') && 
                !statusDropdown.contains(e.target) && 
                e.target !== updateStatusBtn) {
                statusDropdown.classList.remove('active');
            }
        });
    }
}

// History Page Functions
async function loadHistory() {
    try {
        console.log("Loading history with API key:", apiKey ? "Present" : "Missing");
        
        const response = await fetch(`${API_BASE_URL}/user/history`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("History response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("History error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load history');
        }
        
        const history = await response.json();
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
                <img src="empty-history.svg" alt="No history">
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
                    <div class="tiffin-description">${item.description}</div>
                    <div class="tiffin-meta">
                        <span class="tiffin-delivery-time">Delivered at ${formatTime(item.delivery_time)}</span>
                        <span class="tiffin-price">₹${item.price.toFixed(2)}</span>
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
    // Total tiffins
    const totalTiffins = history.filter(item => item.status !== 'cancelled').length;
    document.getElementById('total-tiffins-count').textContent = totalTiffins;
    
    // Total spent
    const totalSpent = history
        .filter(item => item.status !== 'cancelled')
        .reduce((sum, item) => sum + item.price, 0);
    document.getElementById('total-tiffins-spent').textContent = `₹${totalSpent.toFixed(2)}`;
    
    // Most ordered time
    const timeCounts = history
        .filter(item => item.status !== 'cancelled')
        .reduce((counts, item) => {
            counts[item.time] = (counts[item.time] || 0) + 1;
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

// Invoices Page Functions
// Invoices Page Functions
async function loadInvoices() {
    try {
        console.log("Loading invoices with API key:", apiKey ? "Present" : "Missing");
        
        const response = await fetch(`${API_BASE_URL}/user/invoices`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Invoices response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Invoices error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load invoices');
        }
        
        const invoices = await response.json();
        console.log(`Loaded ${invoices.length} invoices`);
        
        displayInvoices(invoices);
        
    } catch (error) {
        console.error('Error loading invoices:', error);
        document.getElementById('invoices-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading invoices: ${error.message}</p>
            </div>
        `;
    }
}

function displayInvoices(invoices) {
    const invoicesList = document.getElementById('invoices-list');
    
    // Sort by date (newest first)
    invoices.sort((a, b) => {
        const dateA = new Date(a.generated_at);
        const dateB = new Date(b.generated_at);
        return dateB - dateA;
    });
    
    if (invoices.length === 0) {
        invoicesList.innerHTML = `
            <div class="empty-state">
                <img src="empty-invoices.svg" alt="No invoices">
                <p>No invoices found</p>
            </div>
        `;
        return;
    }
    
    let invoicesHTML = '';
    
    invoices.forEach(invoice => {
        const statusClass = invoice.paid ? 'paid' : 'unpaid';
        const statusText = invoice.paid ? 'Paid' : 'Unpaid';
        
        invoicesHTML += `
            <div class="invoice-card">
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
                        <div class="invoice-card-tiffin-count">${invoice.tiffins.length}</div>
                    </div>
                    <div class="invoice-card-total">
                        <span>Total Amount</span>
                        <span class="invoice-card-amount">₹${invoice.total_amount.toFixed(2)}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    invoicesList.innerHTML = invoicesHTML;
}

// Profile Page Functions
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

async function loadProfileStats() {
    try {
        console.log("Loading profile stats");
        
        // For user stats, we'll use the user's history
        const response = await fetch(`${API_BASE_URL}/user/history`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Profile stats response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Profile stats error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load user stats');
        }
        
        const history = await response.json();
        console.log(`Loaded ${history.length} history items for stats`);
        
        // Member since
        document.getElementById('member-since').textContent = currentUser.created_at ? 
            formatDate(currentUser.created_at) : 'N/A';
        
        // Total tiffins
        const totalTiffins = history.filter(item => item.status !== 'cancelled').length;
        document.getElementById('profile-total-tiffins').textContent = totalTiffins;
        
        // Most ordered time
        const timeCounts = history
            .filter(item => item.status !== 'cancelled')
            .reduce((counts, item) => {
                counts[item.time] = (counts[item.time] || 0) + 1;
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
        
        document.getElementById('profile-most-ordered').textContent = formatTiffinTime(mostOrderedTime);
        
    } catch (error) {
        console.error('Error loading profile stats:', error);
        document.getElementById('member-since').textContent = 'Error loading data';
        document.getElementById('profile-total-tiffins').textContent = 'Error';
        document.getElementById('profile-most-ordered').textContent = 'Error';
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
        
        const response = await fetch(`${API_BASE_URL}/user/profile`, {
            method: 'PUT',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name,
                email,
                address
            })
        });
        
        console.log("Profile update response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Profile update error details:", errorData);
            throw new Error(errorData.detail || 'Failed to update profile');
        }
        
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
        
        const response = await fetch(`${API_BASE_URL}/user/password`, {
            method: 'PUT',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                old_password: currentPassword,
                new_password: newPassword
            })
        });
        
        console.log("Password change response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Password change error details:", errorData);
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

// Admin Dashboard Functions
async function loadAdminDashboard() {
    if (userRole !== 'admin') {
        console.log("Non-admin user attempted to access admin dashboard");
        return;
    }
    
    try {
        console.log("Loading admin dashboard with API key:", apiKey ? "Present" : "Missing");
        
        const response = await fetch(`${API_BASE_URL}/admin/dashboard`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Admin dashboard response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Admin dashboard error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load admin dashboard');
        }
        
        const stats = await response.json();
        console.log("Admin dashboard stats loaded:", stats);
        
        // Update dashboard stats
        document.getElementById('active-users-count').textContent = stats.total_users;
        document.getElementById('active-tiffins-count').textContent = stats.active_tiffins;
        document.getElementById('monthly-revenue').textContent = `₹${stats.monthly_revenue.toFixed(2)}`;
        document.getElementById('today-deliveries').textContent = stats.today_deliveries;
        
        // Load pending requests
        loadPendingRequests();
        
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
        showNotification('Failed to load dashboard stats: ' + error.message, 'error');
    }
}
async function loadPendingRequests() {
    if (userRole !== 'admin') return;
    
    try {
        console.log("Loading pending requests");
        
        const response = await fetch(`${API_BASE_URL}/admin/tiffin-requests?status=pending`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Pending requests response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Pending requests error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load pending requests');
        }
        
        const requests = await response.json();
        console.log(`Loaded ${requests.length} pending requests`);
        
        const requestsList = document.getElementById('pending-requests-list');
        
        if (requests.length === 0) {
            requestsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty-requests.svg" alt="No requests">
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
// Manage Users Functions
async function loadManageUsers() {
    if (userRole !== 'admin') return;
    
    try {
        console.log("Loading manage users with API key:", apiKey ? "Present" : "Missing");
        
        const response = await fetch(`${API_BASE_URL}/admin/users`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Manage users response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Manage users error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load users');
        }
        
        const users = await response.json();
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
                <img src="empty-users.svg" alt="No users">
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
        
        const response = await fetch(`${API_BASE_URL}/admin/users/${userId}`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("User details response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("User details error:", errorData);
            throw new Error(errorData.detail || 'Failed to fetch user details');
        }
        
        const user = await response.json();
        console.log("User details loaded:", user);
        
        // Fetch user stats
        const statsResponse = await fetch(`${API_BASE_URL}/admin/user/${userId}/stats`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("User stats response status:", statsResponse.status);
        
        if (!statsResponse.ok) {
            const errorData = await statsResponse.json();
            console.error("User stats error:", errorData);
            throw new Error(errorData.detail || 'Failed to fetch user stats');
        }
        
        const stats = await statsResponse.json();
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

// Manage Tiffins Functions
async function loadManageTiffins() {
    if (userRole !== 'admin') return;
    
    console.log("Loading manage tiffins");
    
    // Load users for select dropdowns
    await loadUsersForSelect();
    
    
    // Load existing tiffins
    loadExistingTiffins();
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
        
        let url = `${API_BASE_URL}/admin/tiffins`;
        
        // Add filters if provided
        const queryParams = [];
        if (filters.date) queryParams.push(`date=${filters.date}`);
        if (filters.status) queryParams.push(`status=${filters.status}`);
        
        if (queryParams.length > 0) {
            url += `?${queryParams.join('&')}`;
        }
        
        console.log("Fetching tiffins from:", url);
        
        const response = await fetch(url, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Existing tiffins response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Existing tiffins error:", errorData);
            throw new Error(errorData.detail || 'Failed to load tiffins');
        }
        
        const tiffins = await response.json();
        console.log(`Loaded ${tiffins.length} existing tiffins`);
        
        // Sort by date (newest first) and time
        tiffins.sort((a, b) => {
            const dateA = new Date(a.date);
            const dateB = new Date(b.date);
            if (dateA.getTime() !== dateB.getTime()) {
                return dateB - dateA;
            }
            return a.delivery_time.localeCompare(b.delivery_time);
        });
        
        const tiffinsList = document.getElementById('manage-tiffins-list');
        
        if (tiffins.length === 0) {
            tiffinsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty-tiffins.svg" alt="No tiffins">
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
                        <div class="tiffin-description">${tiffin.description}</div>
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

// Notices & Polls Functions
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
        
        const response = await fetch(`${API_BASE_URL}/user/notices`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Admin notices response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Admin notices error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load notices');
        }
        
        const notices = await response.json();
        console.log(`Loaded ${notices.length} admin notices`);
        
        const noticesList = document.getElementById('admin-notices-list');
        
        if (notices.length === 0) {
            noticesList.innerHTML = `
                <div class="empty-state">
                    <img src="empty-notices.svg" alt="No notices">
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

async function loadAdminPolls() {
    try {
        console.log("Loading admin polls with API key:", apiKey ? "Present" : "Missing");
        
        const response = await fetch(`${API_BASE_URL}/user/polls`, {
            headers: {
                'X-API-Key': apiKey
            }
        });
        
        console.log("Admin polls response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("Admin polls error details:", errorData);
            throw new Error(errorData.detail || 'Failed to load polls');
        }
        
        const polls = await response.json();
        console.log(`Loaded ${polls.length} admin polls`);
        
        const pollsList = document.getElementById('admin-polls-list');
        
        if (polls.length === 0) {
            pollsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty-polls.svg" alt="No polls">
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
        
        polls.forEach(poll => {
            let optionsHTML = '';
            
            poll.options.forEach((option, index) => {
                const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);
                const percentage = totalVotes > 0 ? Math.round((option.votes / totalVotes) * 100) : 0;
                
                optionsHTML += `
                    <div class="poll-option">
                        <span class="poll-option-label">${option.option}</span>
                        <div class="poll-option-progress">
                            <div class="poll-option-bar" style="width: ${percentage}%"></div>
                        </div>
                        <span class="poll-option-percentage">${percentage}% (${option.votes})</span>
                    </div>
                `;
            });
            
            pollsHTML += `
                <div class="poll-card" data-poll-id="${poll._id}">
                    <div class="poll-card-header">
                        <span class="poll-card-title">${poll.question}</span>
                        <span class="poll-status ${poll.active ? 'active' : 'inactive'}">${poll.active ? 'Active' : 'Inactive'}</span>
                    </div>
                    <div class="poll-card-body">
                        <div class="poll-options">
                            ${optionsHTML}
                        </div>
                        <div class="poll-card-footer">
                            <span>Ends: ${formatDate(poll.end_date)}</span>
                            <button class="warning-button delete-poll-btn">Delete</button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        pollsList.innerHTML = pollsHTML;
        
        // Add event listeners to delete buttons
        document.querySelectorAll('.delete-poll-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const pollId = e.target.closest('.poll-card').dataset.pollId;
                deletePoll(pollId);
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

async function deleteNotice(noticeId) {
    showConfirmDialog(
        'Delete Notice',
        'Are you sure you want to delete this notice? This action cannot be undone.',
        async () => {
            try {
                console.log(`Deleting notice: ${noticeId}`);
                
                const response = await fetch(`${API_BASE_URL}/admin/notices/${noticeId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-API-Key': apiKey
                    }
                });
                
                console.log("Delete notice response status:", response.status);
                
                if (!response.ok) {
                    const errorData = await response.json();
                    console.error("Delete notice error:", errorData);
                    throw new Error(errorData.detail || 'Failed to delete notice');
                }
                
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
async function deletePoll(pollId) {
    showConfirmDialog(
        'Delete Poll',
        'Are you sure you want to delete this poll? This action cannot be undone.',
        async () => {
            try {
                console.log(`Deleting poll: ${pollId}`);
                
                const response = await fetch(`${API_BASE_URL}/admin/polls/${pollId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-API-Key': apiKey
                    }
                });
                
                console.log("Delete poll response status:", response.status);
                
                if (!response.ok) {
                    const errorData = await response.json();
                    console.error("Delete poll error:", errorData);
                    throw new Error(errorData.detail || 'Failed to delete poll');
                }
                
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


// Generate Invoices Functions
async function loadGenerateInvoices() {
    if (userRole !== 'admin') return;
    
    // Set default dates (current month)
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().split('T')[0];
    
    document.getElementById('invoice-start-date').value = firstDay;
    document.getElementById('invoice-end-date').value = lastDay;
    
    // Load existing invoices
    loadAdminInvoices();
}

async function loadAdminInvoices(filters = {}) {
    try {
        // This is a simplified approach since there's no direct endpoint to get all invoices
        // In a real app, you'd have an admin/invoices endpoint
        
        // For now, we'll simulate by loading a few recent invoices
        const invoicesList = document.getElementById('admin-invoices-list');
        
        // Example data - in a real app this would come from the API
        const invoices = [
            {
                _id: '61f3c4b2e12e45a789b3c2d1',
                user_id: 'user123',
                start_date: '2023-05-01',
                end_date: '2023-05-31',
                tiffins: Array(15).fill('tiffin'),
                total_amount: 2250.00,
                paid: true,
                generated_at: '2023-06-01T10:00:00.000Z'
            },
            {
                _id: '62a1b3c4d5e6f7g8h9i0j1k2',
                user_id: 'user456',
                start_date: '2023-05-01',
                end_date: '2023-05-31',
                tiffins: Array(12).fill('tiffin'),
                total_amount: 1800.00,
                paid: false,
                generated_at: '2023-06-01T10:00:00.000Z'
            }
        ];
        
        if (invoices.length === 0) {
            invoicesList.innerHTML = `
                <div class="empty-state">
                    <img src="empty-invoices.svg" alt="No invoices">
                    <p>No invoices found</p>
                </div>
            `;
            return;
        }
        
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
                        <div class="invoice-card-user">
                            <strong>User ID:</strong> ${invoice.user_id}
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
                            <div class="invoice-card-tiffin-count">${invoice.tiffins.length}</div>
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
        showNotification('Failed to load invoices', 'error');
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
        
        const response = await fetch(`${API_BASE_URL}/admin/generate-invoices`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                start_date: startDate,
                end_date: endDate
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to generate invoices');
        }
        
        const result = await response.json();
        
        showNotification(`Successfully generated ${result.generated_invoices} invoices`, 'success');
        
        // Reload invoices
        loadAdminInvoices();
        
    } catch (error) {
        console.error('Error generating invoices:', error);
        showNotification(error.message, 'error');
    }
}

async function markInvoicePaid(invoiceId) {
    showConfirmDialog(
        'Mark Invoice as Paid',
        'Are you sure you want to mark this invoice as paid?',
        async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/admin/invoices/${invoiceId}/mark-paid`, {
                    method: 'PUT',
                    headers: {
                        'X-API-Key': apiKey
                    }
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Failed to mark invoice as paid');
                }
                
                showNotification('Invoice marked as paid successfully', 'success');
                
                // Reload invoices
                loadAdminInvoices();
                
            } catch (error) {
                console.error('Error marking invoice as paid:', error);
                showNotification(error.message, 'error');
            }
        }
    );
}

// Helper Functions
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
    
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

function formatTime(timeString) {
    if (!timeString) return 'N/A';
    
    const [hours, minutes] = timeString.split(':');
    const hour = parseInt(hours);
    const ampm = hour >= 12 ? 'PM' : 'AM';
    const hour12 = hour % 12 || 12;
    
    return `${hour12}:${minutes} ${ampm}`;
}

function formatTiffinTime(time) {
    if (!time) return 'N/A';
    
    switch (time) {
        case 'morning':
            return 'Morning';
        case 'afternoon':
            return 'Afternoon';
        case 'evening':
            return 'Evening';
        default:
            return time;
    }
}

function formatTiffinStatus(status) {
    if (!status) return 'N/A';
    
    switch (status) {
        case 'scheduled':
            return 'Scheduled';
        case 'preparing':
            return 'Preparing';
        case 'prepared':
            return 'Prepared';
        case 'out_for_delivery':
            return 'Out for Delivery';
        case 'delivered':
            return 'Delivered';
        case 'cancelled':
            return 'Cancelled';
        default:
            return status;
    }
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

function setupTabs(tabsContainerId, tabBtnClass, tabPaneClass) {
    const tabsContainer = document.getElementById(tabsContainerId);
    if (!tabsContainer) return;
    
    const tabBtns = tabsContainer.querySelectorAll(`.${tabBtnClass}`);
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all tabs
            tabsContainer.querySelectorAll(`.${tabBtnClass}`).forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Add active class to clicked tab
            btn.classList.add('active');
            
            // Get the tab ID
            const tabId = btn.getAttribute('data-tab');
            
            // Hide all tab panes
            document.querySelectorAll(`.${tabPaneClass}`).forEach(pane => {
                pane.classList.remove('active');
            });
            
            // Show selected tab pane
            const targetPane = document.getElementById(`${tabId}-tab`);
            if (targetPane) {
                targetPane.classList.add('active');
            }
        });
    });
}

// Theme Functions
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

// Event Listeners Setup
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
    const noticesTabBtns = document.querySelectorAll('#notices-polls-tabs .tab-btn');
    noticesTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            console.log('Notices tab clicked:', this.getAttribute('data-tab'));
            
            // Remove active class from all tabs
            document.querySelectorAll('#notices-polls-tabs .tab-btn').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Add active class to clicked tab
            this.classList.add('active');
            
            // Hide all tab panes
            document.querySelectorAll('#notices-polls-page .tab-pane').forEach(pane => {
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
    // Login form
    document.getElementById('login-btn').addEventListener('click', async () => {
        const userId = document.getElementById('login-userid').value.trim();
        const password = document.getElementById('login-password').value;
        
        if (!userId || !password) {
            document.getElementById('login-message').textContent = 'Please enter both user ID and password';
            return;
        }
        
        const success = await login(userId, password);
        if (!success) {
            document.getElementById('login-message').textContent = 'Invalid credentials. Please try again.';
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
        .then(tiffins => {
            displayTiffins(tiffins, { date, time, status });
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
        .then(history => {
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
    document.getElementById('add-poll-btn').addEventListener('click', () => {
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
    
    // Menu items
    document.querySelector('.add-menu-item').addEventListener('click', () => {
        const menuItemInput = document.querySelector('.menu-item');
        const menuItem = menuItemInput.value.trim();
        
        if (menuItem) {
            addMenuItem(menuItem, 'menu-items-list');
            menuItemInput.value = '';
        }
    });
    
    document.querySelector('.add-batch-menu-item').addEventListener('click', () => {
        const menuItemInput = document.querySelector('.batch-menu-item');
        const menuItem = menuItemInput.value.trim();
        
        if (menuItem) {
            addMenuItem(menuItem, 'batch-menu-items-list');
            menuItemInput.value = '';
        }
    });
    
    // Create tiffin
    document.getElementById('create-tiffin-btn').addEventListener('click', createTiffin);
    
    // Add user group
    document.getElementById('add-user-group').addEventListener('click', addUserGroup);
    
    // Batch create tiffins
    document.getElementById('batch-create-btn').addEventListener('click', batchCreateTiffins);
    
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
    document.getElementById('mark-all-read').addEventListener('click', () => {
        document.querySelectorAll('.notification-item').forEach(item => {
            item.classList.remove('unread');
        });
        document.getElementById('notification-count').textContent = '0';
        activeNotifications = [];
    });
}

// Form Submission Functions
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

function addPollOption() {
    const container = document.getElementById('poll-options-container');
    const optionCount = container.querySelectorAll('.poll-option-input').length + 1;
    
    const optionDiv = document.createElement('div');
    optionDiv.className = 'poll-option-input';
    optionDiv.innerHTML = `
        <input type="text" class="poll-option" placeholder="Option ${optionCount}">
        <button type="button" class="remove-poll-option">×</button>
    `;
    
    container.appendChild(optionDiv);
    
    // Add event listener to remove button
    optionDiv.querySelector('.remove-poll-option').addEventListener('click', () => {
        container.removeChild(optionDiv);
    });
}

async function createPoll() {
    try {
        const question = document.getElementById('poll-question').value.trim();
        const startDate = document.getElementById('poll-start-date').value;
        const endDate = document.getElementById('poll-end-date').value;
        
        if (!question || !startDate || !endDate) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }
        
        if (new Date(startDate) >= new Date(endDate)) {
            showNotification('End date must be after start date', 'error');
            return;
        }
        
        // Get poll options
        const optionInputs = document.querySelectorAll('.poll-option');
        const options = Array.from(optionInputs)
            .map(input => input.value.trim())
            .filter(option => option);
        
        if (options.length < 2) {
            showNotification('Please add at least 2 options', 'error');
            return;
        }
        
        const poll = {
            question,
            options: options.map(option => ({ option, votes: 0 })),
            start_date: new Date(startDate).toISOString(),
            end_date: new Date(endDate).toISOString(),
            active: true
        };
        
        const response = await fetch(`${API_BASE_URL}/admin/polls`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(poll)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create poll');
        }
        
        showNotification('Poll created successfully', 'success');
        document.getElementById('create-poll-modal').classList.remove('active');
        
        // Clear form
        document.getElementById('poll-question').value = '';
        document.getElementById('poll-start-date').value = '';
        document.getElementById('poll-end-date').value = '';
        document.getElementById('poll-options-container').innerHTML = `
            <div class="poll-option-input">
                <input type="text" class="poll-option" placeholder="Option 1">
            </div>
            <div class="poll-option-input">
                <input type="text" class="poll-option" placeholder="Option 2">
            </div>
        `;
        
        // Reload polls
        loadAdminPolls();
        
    } catch (error) {
        console.error('Error creating poll:', error);
        showNotification(error.message, 'error');
    }
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
        
        const request = {
            description,
            preferred_date: preferredDate,
            preferred_time: preferredTime
        };
        
        if (specialInstructions) {
            request.special_instructions = specialInstructions;
        }
        
        const response = await fetch(`${API_BASE_URL}/user/request-tiffin`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to submit request');
        }
        
        showNotification('Request submitted successfully', 'success');
        document.getElementById('request-tiffin-modal').classList.remove('active');
        
        // Clear form
        document.getElementById('request-description').value = '';
        document.getElementById('request-date').value = '';
        document.getElementById('request-time').value = '';
        document.getElementById('request-instructions').value = '';
        
    } catch (error) {
        console.error('Error submitting tiffin request:', error);
        showNotification(error.message, 'error');
    }
}

function addMenuItem(item, containerId) {
    const container = document.getElementById(containerId);
    
    const itemDiv = document.createElement('div');
    itemDiv.className = 'menu-item-tag';
    itemDiv.innerHTML = `
        ${item}
        <button type="button" class="remove-menu-item">×</button>
    `;
    
    container.appendChild(itemDiv);
    
    // Add event listener to remove button
    itemDiv.querySelector('.remove-menu-item').addEventListener('click', () => {
        container.removeChild(itemDiv);
    });
}

function getMenuItems(containerId) {
    const container = document.getElementById(containerId);
    const items = [];
    
    container.querySelectorAll('.menu-item-tag').forEach(tag => {
        items.push(tag.textContent.trim().replace('×', '').trim());
    });
    
    return items;
}

async function createTiffin() {
    try {
        const date = document.getElementById('tiffin-date').value;
        const time = document.getElementById('tiffin-time').value;
        const description = document.getElementById('tiffin-description').value.trim();
        const price = parseFloat(document.getElementById('tiffin-price').value);
        const cancellationTime = document.getElementById('tiffin-cancellation').value;
        const deliveryTime = document.getElementById('tiffin-delivery').value;
        const menuItems = getMenuItems('menu-items-list');
        
        // Get selected users
        const userSelect = document.getElementById('tiffin-users');
        const assignedUsers = Array.from(userSelect.selectedOptions).map(option => option.value);
        
        if (!date || !time || !description || isNaN(price) || !cancellationTime || !deliveryTime) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }
        
        if (menuItems.length === 0) {
            showNotification('Please add at least one menu item', 'error');
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
            delivery_time: deliveryTime,
            menu_items: menuItems,
            assigned_users: assignedUsers
        };
        
        const response = await fetch(`${API_BASE_URL}/admin/tiffins`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(tiffin)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create tiffin');
        }
        
        showNotification('Tiffin created successfully', 'success');
        
        // Clear form
        document.getElementById('tiffin-date').value = '';
        document.getElementById('tiffin-time').value = '';
        document.getElementById('tiffin-description').value = '';
        document.getElementById('tiffin-price').value = '';
        document.getElementById('tiffin-cancellation').value = '';
        document.getElementById('tiffin-delivery').value = '';
        document.getElementById('menu-items-list').innerHTML = '';
        
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

function addUserGroup() {
    const container = document.getElementById('user-groups-container');
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
    
    container.insertBefore(groupDiv, document.getElementById('add-user-group'));
    
    // Add event listener to remove button
    groupDiv.querySelector('.remove-group-btn').addEventListener('click', () => {
        container.removeChild(groupDiv);
        
                // Update group numbers
        container.querySelectorAll('.user-group').forEach((group, index) => {
            group.querySelector('h4').textContent = `Group ${index + 1}`;
        });
    });
    
    // Populate user select
    const select = groupDiv.querySelector('.user-group-select-input');
    
    fetch(`${API_BASE_URL}/admin/users`, {
        headers: {
            'X-API-Key': apiKey
        }
    })
    .then(response => response.json())
    .then(users => {
        // Filter active users and sort by name
        const activeUsers = users
            .filter(user => user.active)
            .sort((a, b) => a.name.localeCompare(b.name));
        
        activeUsers.forEach(user => {
            const option = document.createElement('option');
            option.value = user.user_id;
            option.textContent = `${user.name} (${user.user_id})`;
            select.appendChild(option);
        });
    })
    .catch(error => {
        console.error('Error loading users for group:', error);
    });
}

async function batchCreateTiffins() {
    try {
        const date = document.getElementById('batch-tiffin-date').value;
        const time = document.getElementById('batch-tiffin-time').value;
        const description = document.getElementById('batch-tiffin-description').value.trim();
        const price = parseFloat(document.getElementById('batch-tiffin-price').value);
        const cancellationTime = document.getElementById('batch-tiffin-cancellation').value;
        const deliveryTime = document.getElementById('batch-tiffin-delivery').value;
        const menuItems = getMenuItems('batch-menu-items-list');
        
        if (!date || !time || !description || isNaN(price) || !cancellationTime || !deliveryTime) {
            showNotification('Please fill in all tiffin details', 'error');
            return;
        }
        
        if (menuItems.length === 0) {
            showNotification('Please add at least one menu item', 'error');
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
            delivery_time: deliveryTime,
            menu_items: menuItems,
            assigned_users: []
        };
        
        const batchData = {
            date,
            time,
            base_tiffin: baseTiffin,
            user_groups: userGroups
        };
        
        const response = await fetch(`${API_BASE_URL}/admin/batch-tiffins`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(batchData)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create batch tiffins');
        }
        
        const result = await response.json();
        showNotification(`Successfully created ${result.created_tiffins.length} tiffins`, 'success');
        
        // Clear form
        document.getElementById('batch-tiffin-date').value = '';
        document.getElementById('batch-tiffin-time').value = '';
        document.getElementById('batch-tiffin-description').value = '';
        document.getElementById('batch-tiffin-price').value = '';
        document.getElementById('batch-tiffin-cancellation').value = '';
        document.getElementById('batch-tiffin-delivery').value = '';
        document.getElementById('batch-menu-items-list').innerHTML = '';
        
        // Reset user groups
        document.getElementById('user-groups-container').innerHTML = `
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
        document.getElementById('add-user-group').addEventListener('click', addUserGroup);
        
        // Switch to manage tab
        document.querySelector('.tab-btn[data-tab="manage-tiffin"]').click();
        
        // Reload tiffins
        loadExistingTiffins();
        
    } catch (error) {
        console.error('Error creating batch tiffins:', error);
        showNotification(error.message, 'error');
    }
}
            
