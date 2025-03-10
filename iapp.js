let currentUser = null;
let userRole = null;
let apiKey = null;
const API_BASE_URL = 'https://tiffintreats-20mb.onrender.com';
let activeNotifications = [];

document.addEventListener('DOMContentLoaded', () => {

    checkAuthentication();

    setupEventListeners();

    initializeTheme();
});

async function apiRequest(endpoint, options = {}) {
    if (!options.headers) {
        options.headers = {};
    }

    if (apiKey) {
        options.headers['X-API-Key'] = apiKey;
        console.log(`Making ${options.method || 'GET'} request to ${endpoint} with API key: ${apiKey ? "Present" : "Missing"}`);
    }

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
                responseData = JSON.parse(text);
            } catch (e) {
                responseData = text;
            }
        }

        if (!response.ok) {
            console.error(`Error from ${endpoint}:`, responseData);

            let errorMessage = 'Request failed';

            if (typeof responseData === 'object') {
                if (responseData.detail) {
                    if (Array.isArray(responseData.detail)) {
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
async function fetchUsersBatch(userIds) {
    try {
        if (!userIds || !userIds.length) return {};
        
        const response = await apiRequest('/admin/users/batch', {
            method: 'POST',
            body: JSON.stringify(userIds)
        });
        
        return response.users || {};
    } catch (error) {
        console.error('Error fetching users batch:', error);
        return {};
    }
}
function checkAuthentication() {
    const savedAuth = localStorage.getItem('tiffinTreatsAuth');

    if (savedAuth) {
        try {
            const auth = JSON.parse(savedAuth);
            apiKey = auth.apiKey;
            userRole = auth.role;

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

            localStorage.setItem('tiffinTreatsAuth', JSON.stringify({
                apiKey: apiKey,
                role: userRole
            }));

            if (userRole === 'admin') {
                currentUser = {
                    name: "Administrator",
                    user_id: "admin",
                    email: "admin@tiffintreats.tech",
                    address: "TiffinTreats Wagholi"
                };
                updateUserInfo();
            } else {

                await fetchUserProfile();
            }

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

function showLogin() {
    document.getElementById('auth-container').classList.remove('hidden');
    document.getElementById('app-container').classList.add('hidden');
}
function showApp() {
    document.getElementById('auth-container').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');

    const adminSection = document.querySelector('.admin-section');
    if (userRole === 'admin') {
        adminSection.classList.remove('hidden');
        // Only setup these forms if admin and after authentication
        setupCreateTiffinForm();
        setupBatchCreateTiffinForm();
    } else {
        adminSection.classList.add('hidden');
    }
}
function navigateTo(pageId) {

    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    const page = document.getElementById(`${pageId}-page`);
    if (page) {
        page.classList.add('active');
    }

    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });

    const activeLink = document.querySelector(`.nav-link[data-page="${pageId}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }

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

    if (window.innerWidth < 992) {
        document.querySelector('.sidebar').classList.remove('active');
    }
}

async function loadDashboard() {
    console.log("Loading dashboard");

    loadNotices();

    loadPolls();

    loadTodayTiffin();

    loadUpcomingTiffins();
}

async function loadNotices() {
    try {
        console.log("Loading notices");

        const response = await apiRequest('/user/notices');
        const notices = response.data || [];

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

        const response = await apiRequest('/user/polls');
        const polls = response.data || [];

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

                if (poll.has_voted) {

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

                    optionsHTML += `<div class="poll-vote-prompt">Please select an option:</div>`;
                    poll.options.forEach((option, index) => {
                        optionsHTML += `
                            <label class="poll-option-btn-container">
                                <input type="radio" name="poll-${poll._id}" value="${index}" class="poll-option-radio">
                                <span class="poll-option-btn-label">${option.option}</span>
                            </label>
                        `;
                    });

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

        const today = new Date().toISOString().split('T')[0]; 
        const response = await apiRequest(`/user/tiffins?date=${today}`);

        console.log("Today's tiffins response:", response);

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

        const now = new Date();
        const currentHour = now.getHours();

        tiffins.sort((a, b) => {
            const timeA = a.time === 'morning' ? 0 : 1; 
            const timeB = b.time === 'morning' ? 0 : 1; 
            return timeA - timeB;
        });

        const nextTiffin = tiffins.find(tiffin => tiffin.status !== 'cancelled');

        if (nextTiffin) {
            todayTiffinStatus.textContent = formatTiffinStatus(nextTiffin.status);

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

        upcomingTiffinsElement.innerHTML = `
            <div class="loading-state">
                <span class="spinner"></span>
                <p>Loading upcoming tiffins...</p>
            </div>
        `;

        const today = new Date().toISOString().split('T')[0];
        const nextWeek = new Date();
        nextWeek.setDate(nextWeek.getDate() + 7);
        const nextWeekStr = nextWeek.toISOString().split('T')[0];

        const response = await apiRequest(`/user/tiffins?date=${today}`);

        const tiffins = response.data || [];

        // Filter out tiffins that are already delivered or cancelled
        const upcomingTiffins = tiffins.filter(tiffin => 
            tiffin.date >= today && 
            tiffin.status !== 'cancelled' && 
            tiffin.status !== 'delivered'
        );

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

        upcomingTiffins.sort((a, b) => {
            if (a.date !== b.date) {
                return a.date.localeCompare(b.date);
            }

            const timeOrder = { 'morning': 0, 'evening': 1 };
            return timeOrder[a.time] - timeOrder[b.time];
        });

        let tiffinsHTML = '';

        const nextTiffins = upcomingTiffins.slice(0, 6);

        for (const tiffin of nextTiffins) {

            if (!tiffin._id || !tiffin.time || !tiffin.status || !tiffin.date) {
                console.warn('Skipping invalid tiffin:', tiffin);
                continue;
            }

            const statusClass = `status-${tiffin.status}`;
            const isCancellable = checkIfCancellable(tiffin);

            const tiffinDate = new Date(tiffin.date);
            const formattedDate = tiffinDate.toLocaleDateString(undefined, {
                weekday: 'short',
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });

            tiffinsHTML += `
                <div class="tiffin-card" data-tiffin-id="${tiffin._id}">
                    <div class="tiffin-header">
                        <span class="tiffin-time">${formatTiffinTime(tiffin.time)}</span>
                        <span class="tiffin-status ${statusClass}">${formatTiffinStatus(tiffin.status)}</span>
                    </div>
                    <div class="tiffin-body">
                        <div class="tiffin-date">${formattedDate}</div>
                        ${userRole === 'admin' && tiffin.description ? 
                            `<div class="tiffin-description">${tiffin.description}</div>` : ''}
                        <div class="tiffin-meta">
                            <span class="tiffin-cancellation-time">Cancel by ${formatTime(tiffin.cancellation_time || '00:00')}</span>
                            <span class="tiffin-price">₹${(tiffin.price || 0).toFixed(2)}</span>
                        </div>
                        <div class="tiffin-actions">
                            ${isCancellable ? 
                                `<button class="cancel-tiffin-btn secondary-button" data-tiffin-id="${tiffin._id}">Cancel</button>` : 
                                `<button class="view-details-btn secondary-button" data-tiffin-id="${tiffin._id}">View Details</button>`
                            }
                        </div>
                    </div>
                </div>
            `;
        }

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

        document.querySelectorAll('.tiffin-card').forEach(card => {
            card.addEventListener('click', (e) => {
                if (!e.target.classList.contains('cancel-tiffin-btn') && 
                    !e.target.classList.contains('view-details-btn')) {
                    const tiffinId = e.currentTarget.dataset.tiffinId;
                    if (tiffinId) {
                        showTiffinDetails(tiffinId);
                    }
                }
            });
        });

        document.querySelectorAll('.cancel-tiffin-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const tiffinId = e.target.dataset.tiffinId;
                cancelTiffin(tiffinId);
            });
        });

        document.querySelectorAll('.view-details-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const tiffinId = e.target.dataset.tiffinId;
                showTiffinDetails(tiffinId);
            });
        });

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

async function loadTiffins(page = 1, limit = 9) {
    try {
        console.log("Loading tiffins with API key:", apiKey ? "Present" : "Missing");

        const queryParams = [`skip=${(page - 1) * limit}`, `limit=${limit}`];
        const queryString = `?${queryParams.join('&')}`;

        const response = await apiRequest(`/user/tiffins${queryString}`);

        console.log("Tiffins response:", response);

        const tiffins = response.data || [];
        const totalTiffins = response.total || 0;
        console.log(`Loaded ${tiffins.length} tiffins out of ${totalTiffins} total`);

        displayTiffins(tiffins, {}, page, limit, totalTiffins);

    } catch (error) {
        console.error('Error loading tiffins:', error);
        document.getElementById('tiffins-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading tiffins: ${error.message}</p>
            </div>
        `;
    }
}

function displayTiffins(tiffins, filters = {}, currentPage = 1, limit = 9, totalItems = 0) {
    const tiffinsList = document.getElementById('tiffins-list');

    if (!tiffinsList) {
        console.error("Tiffins list element not found");
        return;
    }

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

    filteredTiffins.sort((a, b) => {
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        if (dateA.getTime() !== dateB.getTime()) {
            return dateB - dateA;
        }

        return a.time === 'morning' ? -1 : 1;
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
        const isCancellable = checkIfCancellable(tiffin);

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
                        ${isCancellable && tiffin.status !== 'cancelled' ? 
                            `<button class="cancel-tiffin-btn secondary-button" data-tiffin-id="${tiffin._id}">Cancel</button>` : 
                            `<button class="view-details-btn secondary-button" data-tiffin-id="${tiffin._id}">View Details</button>`
                        }
                    </div>
                </div>
            </div>
        `;
    });

    // Add pagination controls if total count is available
    let paginationHTML = '';
    if (totalItems > 0) {
        const totalPages = Math.ceil(totalItems / limit);
        
        if (totalPages > 1) {
            paginationHTML = '<div class="pagination-controls">';
            
            if (currentPage > 1) {
                paginationHTML += `<button class="pagination-btn" data-page="${currentPage-1}">Previous</button>`;
            }
            
            // Show page numbers
            const startPage = Math.max(1, currentPage - 2);
            const endPage = Math.min(totalPages, currentPage + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                paginationHTML += `<button class="pagination-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
            }
            
            if (currentPage < totalPages) {
                paginationHTML += `<button class="pagination-btn" data-page="${currentPage+1}">Next</button>`;
            }
            
            paginationHTML += '</div>';
        }
    }

    tiffinsList.innerHTML = tiffinsHTML + paginationHTML;

    document.querySelectorAll('.tiffin-card').forEach(card => {
        card.addEventListener('click', (e) => {
            if (!e.target.classList.contains('cancel-tiffin-btn') && 
                !e.target.classList.contains('view-details-btn')) {
                const tiffinId = e.currentTarget.dataset.tiffinId;
                showTiffinDetails(tiffinId);
            }
        });
    });

    document.querySelectorAll('.cancel-tiffin-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const tiffinId = e.target.dataset.tiffinId;
            cancelTiffin(tiffinId);
        });
    });

    document.querySelectorAll('.view-details-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const tiffinId = e.target.dataset.tiffinId;
            showTiffinDetails(tiffinId);
        });
    });

    // Add event listeners for pagination buttons
    document.querySelectorAll('.pagination-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const pageNum = parseInt(btn.dataset.page);
            loadTiffins(pageNum, limit);
        });
    });
}

function checkIfCancellable(tiffin) {
    if (!tiffin || tiffin.status === 'delivered' || tiffin.status === 'cancelled') {
        return false;
    }

    try {
        const today = new Date().toISOString().split('T')[0];
        const tiffinDate = tiffin.date;

        if (tiffinDate > today) {
            return true;
        }

        if (tiffinDate === today) {
            const now = new Date();
            const [hours, minutes] = (tiffin.cancellation_time || '00:00').split(':');
            const cancellationTime = new Date();
            cancellationTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);

            return now < cancellationTime;
        }

        return false;
    } catch (error) {
        console.error('Error checking if tiffin is cancellable:', error);
        return false;
    }
}

async function showTiffinDetails(tiffinId) {
    try {
        if (!tiffinId || typeof tiffinId !== 'string') {
            throw new Error('Invalid tiffin ID');
        }

        console.log(`Loading details for tiffin ID: ${tiffinId}`);
        const tiffin = await fetchTiffinDetails(tiffinId);

        document.getElementById('tiffin-details-date').textContent = formatDate(tiffin.date);
        document.getElementById('tiffin-details-time').textContent = formatTiffinTime(tiffin.time);

        const descriptionSection = document.getElementById('tiffin-details-description-section');
        if (userRole === 'admin' && tiffin.description) {
            descriptionSection.classList.remove('hidden');
            document.getElementById('tiffin-details-description').textContent = tiffin.description || 'No description available';
        } else {
            descriptionSection.classList.add('hidden');
        }

        document.getElementById('tiffin-details-price').textContent = `₹${(tiffin.price || 0).toFixed(2)}`;
        document.getElementById('tiffin-details-cancellation-time').textContent = formatTime(tiffin.cancellation_time || '00:00');

        const statusElement = document.getElementById('tiffin-details-status');
        statusElement.textContent = formatTiffinStatus(tiffin.status);
        statusElement.className = `status-${tiffin.status}`;

        await loadTiffinCancellations(tiffinId);

        const usersContainer = document.getElementById('tiffin-details-users');
        if (usersContainer) {
            usersContainer.innerHTML = '';

            if (userRole === 'admin' && tiffin.assigned_users && tiffin.assigned_users.length > 0) {
                // Fetch all users in one batch request
                const usersBatch = await fetchUsersBatch(tiffin.assigned_users);
                
                for (const userId of tiffin.assigned_users) {
                    const userDetails = usersBatch[userId];
                    const userDiv = document.createElement('div');
                    userDiv.className = 'assigned-user';
                    userDiv.textContent = userDetails && userDetails.name ? 
                        `${userDetails.name} (${userId})` : userId;
                    usersContainer.appendChild(userDiv);
                }
            } else if (userRole === 'admin') {
                usersContainer.innerHTML = '<div class="empty-message">No users assigned</div>';
            } else {
                const userSection = document.querySelector('.tiffin-details-section.admin-only');
                if (userSection) {
                    userSection.style.display = 'none';
                }
            }
        }

        // Rest of the function remains the same
        const adminActions = document.querySelector('.tiffin-details-actions.admin-only');
        const userActions = document.querySelector('.tiffin-details-actions.user-only');

        if (userRole === 'admin') {
            if (adminActions) adminActions.style.display = 'block';
            if (userActions) userActions.style.display = 'none';
        } else {
            if (adminActions) adminActions.style.display = 'none';
            if (userActions) userActions.style.display = 'block';

            const cancelBtn = document.getElementById('cancel-tiffin-btn');
            if (cancelBtn) {
                if (tiffin.status === 'delivered' || tiffin.status === 'cancelled') {
                    cancelBtn.style.display = 'none';
                } else {
                    const today = new Date().toISOString().split('T')[0];
                    const tiffinDate = new Date(tiffin.date);
                    const now = new Date();

                    if (tiffin.date > today) {
                        cancelBtn.style.display = 'block';
                        cancelBtn.onclick = () => cancelTiffin(tiffin._id);
                    } else if (tiffin.date === today) {
                        const [hours, minutes] = tiffin.cancellation_time.split(':');
                        const cancellationTime = new Date();
                        cancellationTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);

                        if (now < cancellationTime) {
                            cancelBtn.style.display = 'block';
                            cancelBtn.onclick = () => cancelTiffin(tiffin._id);
                        } else {
                            cancelBtn.style.display = 'none';
                        }
                    } else {
                        cancelBtn.style.display = 'none';
                    }
                }
            }
        }

        const modal = document.getElementById('tiffin-details-modal');
        if (modal) {
            modal.dataset.tiffinId = tiffin._id;
            modal.classList.add('active');

            const closeBtn = modal.querySelector('.close-modal');
            if (closeBtn) {
                const newCloseBtn = closeBtn.cloneNode(true);
                closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);

                newCloseBtn.addEventListener('click', () => {
                    modal.classList.remove('active');
                });
            }

            if (userRole === 'admin') {
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

            cancellationsSection.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Error loading cancellations:', error);

        const cancellationsSection = document.getElementById('tiffin-details-cancellations');
        if (cancellationsSection) {
            cancellationsSection.classList.add('hidden');
        }
    }
}

function fixTiffinStatusUpdate() {
    console.log("Fixing tiffin status update functionality");

    const modal = document.getElementById('tiffin-details-modal');
    if (!modal || !modal.classList.contains('active')) {
        console.log("Tiffin details modal not active");
        return;
    }

    const tiffinId = modal.dataset.tiffinId;
    if (!tiffinId) {
        console.log("No tiffin ID found in modal");
        return;
    }

    console.log("Tiffin ID:", tiffinId);

    const adminActions = modal.querySelector('.tiffin-details-actions.admin-only');
    if (!adminActions) {
        console.log("Admin actions section not found");
        return;
    }

    adminActions.innerHTML = '';

    const statusSelect = document.createElement('select');
    statusSelect.id = 'tiffin-status-select';
    statusSelect.className = 'form-control';

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

    const updateButton = document.createElement('button');
    updateButton.textContent = 'Update Status';
    updateButton.className = 'action-button';
    updateButton.style.marginLeft = '10px';

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

            const statusElement = document.getElementById('tiffin-details-status');
            if (statusElement) {
                statusElement.textContent = formatTiffinStatus(newStatus);
                statusElement.className = `status-${newStatus}`;
            }

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

        let tiffin;

        if (userRole === 'admin') {
            tiffin = await apiRequest(`/admin/tiffins/${tiffinId}`);
        } else {

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

                    await apiRequest(`/user/cancel-tiffin?tiffin_id=${tiffinId}`, {
                        method: 'POST'
                    });

                    showNotification('Tiffin cancelled successfully', 'success');

                    const modal = document.getElementById('tiffin-details-modal');
                    if (modal && modal.classList.contains('active')) {
                        modal.classList.remove('active');
                    }

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

async function loadHistory(page = 1, limit = 9) {
    try {
        console.log("Loading history with API key:", apiKey ? "Present" : "Missing");

        const queryParams = [`skip=${(page - 1) * limit}`, `limit=${limit}`];
        const queryString = `?${queryParams.join('&')}`;

        const response = await apiRequest(`/user/history${queryString}`);

        console.log("History response:", response);

        const history = response.data || [];
        const totalItems = response.total || 0;
        console.log(`Loaded ${history.length} history items out of ${totalItems} total`);

        displayHistory(history, {}, page, limit, totalItems);
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

function displayHistory(history, filters = {}, currentPage = 1, limit = 9, totalItems = 0) {
    const historyList = document.getElementById('history-list');

    let filteredHistory = history;

    if (filters.startDate) {
        filteredHistory = filteredHistory.filter(item => item.date >= filters.startDate);
    }

    if (filters.endDate) {
        filteredHistory = filteredHistory.filter(item => item.date <= filters.endDate);
    }

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

    // Add pagination controls if total count is available
    let paginationHTML = '';
    if (totalItems > 0) {
        const totalPages = Math.ceil(totalItems / limit);
        
        if (totalPages > 1) {
            paginationHTML = '<div class="pagination-controls">';
            
            if (currentPage > 1) {
                paginationHTML += `<button class="pagination-btn" data-page="${currentPage-1}">Previous</button>`;
            }
            
            // Show page numbers
            const startPage = Math.max(1, currentPage - 2);
            const endPage = Math.min(totalPages, currentPage + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                paginationHTML += `<button class="pagination-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
            }
            
            if (currentPage < totalPages) {
                paginationHTML += `<button class="pagination-btn" data-page="${currentPage+1}">Next</button>`;
            }
            
            paginationHTML += '</div>';
        }
    }

    historyList.innerHTML = historyHTML + paginationHTML;

    document.querySelectorAll('.tiffin-card').forEach(card => {
        card.addEventListener('click', (e) => {
            const tiffinId = e.currentTarget.dataset.tiffinId;
            showTiffinDetails(tiffinId);
        });
    });

    // Add event listeners for pagination buttons
    document.querySelectorAll('.pagination-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const pageNum = parseInt(btn.dataset.page);
            loadHistory(pageNum, limit);
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

    const totalTiffins = history.filter(item => item.status !== 'cancelled').length;
    document.getElementById('total-tiffins-count').textContent = totalTiffins;

    const totalSpent = history
        .filter(item => item.status !== 'cancelled')
        .reduce((sum, item) => sum + (item.price || 0), 0);
    document.getElementById('total-tiffins-spent').textContent = `₹${totalSpent.toFixed(2)}`;

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

async function loadInvoices(page = 1, limit = 9) {
    try {
        console.log("Loading invoices with API key:", apiKey ? "Present" : "Missing");

        const queryParams = [`skip=${(page - 1) * limit}`, `limit=${limit}`];
        const queryString = `?${queryParams.join('&')}`;

        const response = await apiRequest(`/user/invoices${queryString}`);
        console.log("Invoices response:", response);

        const invoices = response.data || [];
        const totalItems = response.total || 0;
        console.log(`Loaded ${invoices.length} invoices out of ${totalItems} total`);

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

        // Add pagination controls if total count is available
        let paginationHTML = '';
        if (totalItems > 0) {
            const totalPages = Math.ceil(totalItems / limit);
            
            if (totalPages > 1) {
                paginationHTML = '<div class="pagination-controls">';
                
                if (page > 1) {
                    paginationHTML += `<button class="pagination-btn" data-page="${page-1}">Previous</button>`;
                }
                
                // Show page numbers
                const startPage = Math.max(1, page - 2);
                const endPage = Math.min(totalPages, page + 2);
                
                for (let i = startPage; i <= endPage; i++) {
                    paginationHTML += `<button class="pagination-btn ${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
                }
                
                if (page < totalPages) {
                    paginationHTML += `<button class="pagination-btn" data-page="${page+1}">Next</button>`;
                }
                
                paginationHTML += '</div>';
            }
        }

        invoicesList.innerHTML = invoicesHTML + paginationHTML;

        document.querySelectorAll('.view-invoice-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const invoiceId = e.target.dataset.invoiceId;
                viewInvoiceDetails(invoiceId);
            });
        });

        // Add event listeners for pagination buttons
        document.querySelectorAll('.pagination-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const pageNum = parseInt(btn.dataset.page);
                loadInvoices(pageNum, limit);
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

        modal.querySelector('.close-modal').addEventListener('click', () => {
            document.body.removeChild(modal);
        });

    } catch (error) {
        console.error('Error showing invoice details:', error);
        showNotification('Failed to load invoice details: ' + error.message, 'error');
    }
}

async function loadProfile() {
    try {
        console.log("Loading profile");

        await fetchUserProfile();

        await loadProfileStats();

    } catch (error) {
        console.error('Error loading profile:', error);
        showNotification('Failed to load profile data: ' + error.message, 'error');
    }
}

async function fetchUserProfile() {
    try {
        console.log("Fetching user profile, role:", userRole);

        if (userRole === 'admin') {
            console.log("Admin user, creating default profile");
            currentUser = {
                name: "Administrator",
                user_id: "admin",
                email: "admin@tiffintreats.com",
                address: "TiffinTreats HQ"
            };

            updateUserInfo();
            return currentUser;
        }

        console.log("Fetching profile with API key:", apiKey ? apiKey.substring(0, 5) + "..." : "Missing");

        const userProfile = await apiRequest('/user/profile');

        console.log("Profile data received:", userProfile);

        currentUser = userProfile;

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

        const response = await fetch(`${API_BASE_URL}/user/password?old_password=${encodeURIComponent(currentPassword)}&new_password=${encodeURIComponent(newPassword)}`, {
            method: 'PUT',
            headers: {
                'X-API-Key': apiKey
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to change password');
        }

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

        if (userRole === 'admin') {
            document.getElementById('profile-total-tiffins').textContent = 'N/A';
            document.getElementById('profile-most-ordered').textContent = 'N/A';
            return;
        }

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

    document.getElementById('user-name').textContent = currentUser.name || 'User';
    document.getElementById('user-initial').textContent = getInitials(currentUser.name || 'User');

    document.getElementById('user-role').textContent = userRole === 'admin' ? 'Administrator' : 'User';

    const adminSection = document.querySelector('.admin-section');
    if (adminSection) {
        if (userRole === 'admin') {
            adminSection.classList.remove('hidden');
        } else {
            adminSection.classList.add('hidden');
        }
    }

    updateProfilePage();
}

function updateProfilePage() {

    if (!document.getElementById('profile-name')) return;

    document.getElementById('profile-name').textContent = currentUser.name || 'User';
    document.getElementById('profile-user-id').textContent = currentUser.user_id || '';
    document.getElementById('profile-initial').textContent = getInitials(currentUser.name || 'User');

    document.getElementById('profile-edit-name').value = currentUser.name || '';
    document.getElementById('profile-edit-email').value = currentUser.email || '';
    document.getElementById('profile-edit-address').value = currentUser.address || '';

    if (currentUser.created_at) {
        document.getElementById('member-since').textContent = formatDate(currentUser.created_at);
    }
}

async function loadNotifications() {
    try {
                const response = await apiRequest('/user/notifications');

        const notifications = response.notifications || [];
        const unreadCount = response.unread_count || 0;

        document.getElementById('notification-count').textContent = unreadCount;

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

            notificationItem.addEventListener('click', () => {
                markNotificationRead(notification._id);
            });

            notificationList.appendChild(notificationItem);
        });

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
            body: JSON.stringify([notificationId])  
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to mark notification as read');
        }

        const notificationItem = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
        if (notificationItem) {
            notificationItem.classList.remove('unread');
        }

        const unreadCount = parseInt(document.getElementById('notification-count').textContent) - 1;
        document.getElementById('notification-count').textContent = Math.max(0, unreadCount);

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

        document.querySelectorAll('.notification-item.unread').forEach(item => {
            item.classList.remove('unread');
        });

        document.getElementById('notification-count').textContent = '0';

        activeNotifications = [];

        showNotification('All notifications marked as read', 'success');

    } catch (error) {
        console.error('Error marking all notifications as read:', error);
        showNotification('Failed to mark notifications as read', 'error');
    }
}

async function loadAdminDashboard() {
    if (userRole !== 'admin') return;

    try {
        console.log("Loading admin dashboard with API key:", apiKey ? "Present" : "Missing");

        const stats = await apiRequest('/admin/dashboard');

        console.log("Admin dashboard stats loaded:", stats);

        document.getElementById('active-users-count').textContent = stats.total_users;
        document.getElementById('active-tiffins-count').textContent = stats.active_tiffins;
        document.getElementById('monthly-revenue').textContent = `₹${stats.monthly_revenue.toFixed(2)}`;
        document.getElementById('today-deliveries').textContent = stats.today_deliveries;

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

        loadPendingRequests();

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

        const response = await apiRequest('/admin/tiffin-requests?status=pending');
        
        // Handle different response formats
        const requests = Array.isArray(response) ? response : 
                        (Array.isArray(response?.data) ? response.data : []);

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

        for (const request of requests) {

            let userName = request.user_id;
            try {
                const userDetails = await apiRequest(`/admin/users/${request.user_id}`);
                if (userDetails && userDetails.name) {
                    userName = userDetails.name;
                }
            } catch (error) {
                console.warn(`Couldn't fetch details for user ${request.user_id}:`, error);
            }

            requestsHTML += `
                <div class="request-card">
                    <div class="request-header">
                        <span>Request from ${userName} (${request.user_id})</span>
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
        }

        requestsList.innerHTML = requestsHTML;

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

        const newCard = card.cloneNode(true);
        card.parentNode.replaceChild(newCard, card);

        newCard.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = newCard.getAttribute('data-page');
            if (pageId) {
                navigateTo(pageId);
            }
        });
    });
}

async function loadManageUsers(page = 1, limit = 9, searchQuery = '') {
    if (userRole !== 'admin') return;

    try {
        console.log("Loading manage users with API key:", apiKey ? "Present" : "Missing");

        const queryParams = [`skip=${(page - 1) * limit}`, `limit=${limit}`];
        if (searchQuery) {
            queryParams.push(`search=${encodeURIComponent(searchQuery)}`);
        }
        const queryString = `?${queryParams.join('&')}`;

        const response = await apiRequest(`/admin/users${queryString}`);

        console.log("Response from manage users:", response);
        
        const users = response.users || [];
        const totalUsers = response.total || 0;
        console.log(`Loaded ${users.length} users out of ${totalUsers} total`);

        displayUsers(users, searchQuery, page, limit, totalUsers);

    } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('users-list').innerHTML = `
            <div class="empty-state">
                <p>Error loading users: ${error.message}</p>
            </div>
        `;
    }
}

function displayUsers(users, searchQuery = '', currentPage = 1, limit = 9, totalItems = 0) {
    const usersList = document.getElementById('users-list');

    let filteredUsers = users;
    if (searchQuery) {
        const query = searchQuery.toLowerCase();
        filteredUsers = users.filter(user => 
            user.name.toLowerCase().includes(query) || 
            user.user_id.toLowerCase().includes(query) || 
            user.email.toLowerCase().includes(query)
        );
    }

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

    // Add pagination controls
    let paginationHTML = '';
    if (totalItems > 0) {
        const totalPages = Math.ceil(totalItems / limit);
        
        if (totalPages > 1) {
            paginationHTML = '<div class="pagination-controls">';
            
            if (currentPage > 1) {
                paginationHTML += `<button class="pagination-btn" data-page="${currentPage-1}">Previous</button>`;
            }
            
            // Show page numbers
            const startPage = Math.max(1, currentPage - 2);
            const endPage = Math.min(totalPages, currentPage + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                paginationHTML += `<button class="pagination-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
            }
            
            if (currentPage < totalPages) {
                paginationHTML += `<button class="pagination-btn" data-page="${currentPage+1}">Next</button>`;
            }
            
            paginationHTML += '</div>';
        }
    }

    usersList.innerHTML = usersHTML + paginationHTML;

    document.querySelectorAll('.user-card').forEach(card => {
        card.addEventListener('click', (e) => {
            const userId = e.currentTarget.dataset.userId;
            showUserDetails(userId);
        });
    });

    // Add event listeners for pagination buttons
    document.querySelectorAll('.pagination-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const pageNum = parseInt(btn.dataset.page);
            loadManageUsers(pageNum, limit, searchQuery);
        });
    });
}

async function showUserDetails(userId) {
    if (userRole !== 'admin') return;

    try {
        console.log(`Loading details for user: ${userId}`);

        const user = await apiRequest(`/admin/users/${userId}`);
        console.log("User details loaded:", user);

        const stats = await apiRequest(`/admin/user/${userId}/stats`);
        console.log("User stats loaded:", stats);

        document.getElementById('user-details-name').textContent = user.name;
        document.getElementById('user-details-user-id').textContent = user.user_id;
        document.getElementById('user-details-user-email').textContent = user.email;
        document.getElementById('user-details-address').textContent = user.address;
        document.getElementById('user-details-initial').textContent = getInitials(user.name);

        document.getElementById('user-details-member-since').textContent = formatDate(stats.active_since);
        document.getElementById('user-details-total-tiffins').textContent = stats.total_tiffins;
        document.getElementById('user-details-cancelled-tiffins').textContent = stats.cancelled_tiffins;
        document.getElementById('user-details-total-spent').textContent = `₹${stats.total_spent.toFixed(2)}`;

        const toggleStatusBtn = document.getElementById('toggle-user-status-btn');
        toggleStatusBtn.textContent = user.active ? 'Deactivate User' : 'Activate User';
        toggleStatusBtn.className = user.active ? 'warning-button' : 'action-button';

        document.getElementById('edit-user-name').value = user.name;
        document.getElementById('edit-user-email').value = user.email;
        document.getElementById('edit-user-address').value = user.address;
        document.getElementById('edit-user-active').value = user.active.toString();

        setupUserDetailsListeners(user);

        document.getElementById('user-details-modal').classList.add('active');

    } catch (error) {
        console.error('Error showing user details:', error);
        showNotification('Failed to load user details: ' + error.message, 'error');
    }
}

function setupUserDetailsListeners(user) {

    document.querySelector('#user-details-modal .close-modal').addEventListener('click', () => {
        document.getElementById('user-details-modal').classList.remove('active');
        document.querySelector('.user-details-content').classList.remove('hidden');
        document.querySelector('.edit-user-form').classList.add('hidden');
    });

    document.getElementById('edit-user-btn').onclick = () => {
        document.querySelector('.user-details-content').classList.add('hidden');
        document.querySelector('.edit-user-form').classList.remove('hidden');
    };

    document.getElementById('cancel-edit-user-btn').onclick = () => {
        document.querySelector('.user-details-content').classList.remove('hidden');
        document.querySelector('.edit-user-form').classList.add('hidden');
    };

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

            loadManageUsers();

        } catch (error) {
            console.error('Error updating user:', error);
            showNotification(error.message, 'error');
        }
    };

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

        document.getElementById('new-user-id').value = '';
        document.getElementById('new-user-name').value = '';
        document.getElementById('new-user-email').value = '';
        document.getElementById('new-user-address').value = '';
        document.getElementById('new-user-password').value = '';

        loadManageUsers();

    } catch (error) {
        console.error('Error creating user:', error);
        showNotification(error.message, 'error');
    }
}

async function loadManageTiffins() {
    if (userRole !== 'admin') return;

    console.log("Loading manage tiffins");

    // Load users first for the select dropdowns
    await loadUsersForSelect();

    // Then load existing tiffins
    loadExistingTiffins();

    // Setup tabs and forms
    setupTiffinTabs();
    setupCreateTiffinForm();
    setupBatchCreateTiffinForm();
}

function setupTiffinTabs() {
    const tiffinTabBtns = document.querySelectorAll('.tiffin-management-tabs .tab-btn');
    tiffinTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            console.log('Tiffin tab clicked:', this.getAttribute('data-tab'));

            document.querySelectorAll('.tiffin-management-tabs .tab-btn').forEach(tab => {
                tab.classList.remove('active');
            });

            this.classList.add('active');

            document.querySelectorAll('#manage-tiffins-page .tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });

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

    const createTiffinForm = document.getElementById('create-tiffin-tab');
    if (!createTiffinForm) return;

    const descriptionLabel = createTiffinForm.querySelector('label[for="tiffin-description"]');
    if (descriptionLabel) {
        descriptionLabel.textContent = 'Description (Optional)';
    }

    const descriptionTextarea = document.getElementById('tiffin-description');
    if (descriptionTextarea) {
        descriptionTextarea.removeAttribute('required');
        descriptionTextarea.placeholder = 'Optional description of tiffin contents';
    }

    const deliveryTimeSection = createTiffinForm.querySelector('.form-group:has(#tiffin-delivery)');
    if (deliveryTimeSection) {
        deliveryTimeSection.remove();
    }

    const createTiffinBtn = document.getElementById('create-tiffin-btn');
    if (createTiffinBtn) {

        const newCreateTiffinBtn = createTiffinBtn.cloneNode(true);
        createTiffinBtn.parentNode.replaceChild(newCreateTiffinBtn, createTiffinBtn);

        newCreateTiffinBtn.addEventListener('click', createTiffinWithoutMenuItems);
    }
}

function createTiffinWithoutMenuItems() {
    try {
        const date = document.getElementById('tiffin-date').value;
        const time = document.getElementById('tiffin-time').value;
        const description = document.getElementById('tiffin-description').value.trim();
        const price = parseFloat(document.getElementById('tiffin-price').value);
        const cancellationTime = document.getElementById('tiffin-cancellation').value;

        const userSelect = document.getElementById('tiffin-users');
        const assignedUsers = Array.from(userSelect.selectedOptions).map(option => option.value);

        if (!date || !time || isNaN(price) || !cancellationTime) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }

        if (assignedUsers.length === 0) {
            showNotification('Please assign at least one user', 'error');
            return;
        }

        let finalCancellationTime = cancellationTime;
        if (!cancellationTime) {
            finalCancellationTime = time === 'morning' ? '07:00' : '17:00';
        }

        const tiffin = {
            date,
            time,

            ...(description && { description }),
            price,
            cancellation_time: finalCancellationTime,
            assigned_users: assignedUsers,
            status: "scheduled"
        };

        const createBtn = document.getElementById('create-tiffin-btn');
        if (createBtn) {
            createBtn.disabled = true;
            createBtn.innerHTML = '<span class="spinner"></span> Creating...';
        }

        apiRequest('/admin/tiffins', {
            method: 'POST',
            body: JSON.stringify(tiffin)
        })
        .then(result => {
            showNotification('Tiffin created successfully', 'success');

            document.getElementById('tiffin-date').value = '';
            document.getElementById('tiffin-time').value = '';
            document.getElementById('tiffin-description').value = '';
            document.getElementById('tiffin-price').value = '';
            document.getElementById('tiffin-cancellation').value = '';

            Array.from(userSelect.options).forEach(option => {
                option.selected = false;
            });

            document.querySelector('.tab-btn[data-tab="manage-tiffin"]').click();

            loadExistingTiffins();
        })
        .catch(error => {
            console.error('Error creating tiffin:', error);
            showNotification(error.message, 'error');
        })
        .finally(() => {

            if (createBtn) {
                createBtn.disabled = false;
                createBtn.textContent = 'Create Tiffin';
            }
        });

    } catch (error) {
        console.error('Error creating tiffin:', error);
        showNotification(error.message, 'error');

        const createBtn = document.getElementById('create-tiffin-btn');
        if (createBtn) {
            createBtn.disabled = false;
            createBtn.textContent = 'Create Tiffin';
        }
    }
}

function setupBatchCreateTiffinForm() {
    

    const batchCreateTiffinForm = document.getElementById('batch-create-tab');
    if (!batchCreateTiffinForm) return;

    const descriptionLabel = batchCreateTiffinForm.querySelector('label[for="batch-tiffin-description"]');
    if (descriptionLabel) {
        descriptionLabel.textContent = 'Description (Optional)';
    }

    const descriptionTextarea = document.getElementById('batch-tiffin-description');
    if (descriptionTextarea) {
        descriptionTextarea.removeAttribute('required');
        descriptionTextarea.placeholder = 'Optional description of tiffin contents';
    }

    const deliveryTimeSection = batchCreateTiffinForm.querySelector('.form-group:has(#batch-tiffin-delivery)');
    if (deliveryTimeSection) {
        deliveryTimeSection.remove();
    }

    const batchCreateBtn = document.getElementById('batch-create-btn');
    if (batchCreateBtn) {

        const newBatchCreateBtn = batchCreateBtn.cloneNode(true);
        batchCreateBtn.parentNode.replaceChild(newBatchCreateBtn, batchCreateBtn);

        newBatchCreateBtn.addEventListener('click', batchCreateTiffinsWithoutMenuItems);
    }
    resetUserGroups();
}

function batchCreateTiffinsWithoutMenuItems() {
    try {
        const date = document.getElementById('batch-tiffin-date').value;
        const time = document.getElementById('batch-tiffin-time').value;
        const description = document.getElementById('batch-tiffin-description').value.trim();
        const basePrice = parseFloat(document.getElementById('batch-tiffin-price').value);
        const cancellationTime = document.getElementById('batch-tiffin-cancellation').value;

        if (!date || !time || isNaN(basePrice) || !cancellationTime) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }

        // Create user groups with prices
        const userGroups = [];
        document.querySelectorAll('.user-group').forEach(group => {
            const select = group.querySelector('.user-group-select-input');
            const users = Array.from(select.selectedOptions).map(option => option.value);
            
            // Get the group-specific price input if it exists, otherwise use the base price
            let groupPrice = basePrice;
            const groupPriceInput = group.querySelector('.group-price-input');
            if (groupPriceInput) {
                const inputPrice = parseFloat(groupPriceInput.value);
                if (!isNaN(inputPrice)) {
                    groupPrice = inputPrice;
                }
            }

            if (users.length > 0) {
                userGroups.push({
                    users: users,
                    price: groupPrice
                });
            }
        });

        if (userGroups.length === 0) {
            showNotification('Please add at least one user group with selected users', 'error');
            return;
        }

        let finalCancellationTime = cancellationTime;
        if (!cancellationTime) {
            finalCancellationTime = time === 'morning' ? '07:00' : '17:00';
        }

        const baseTiffin = {
            date,
            time,
            ...(description && { description }),
            price: basePrice, // This is now just the default price
            cancellation_time: finalCancellationTime,
            status: "scheduled"
        };

        const batchCreateBtn = document.getElementById('batch-create-btn');
        batchCreateBtn.disabled = true;
        batchCreateBtn.innerHTML = '<span class="spinner"></span> Creating...';

        fetch(`${API_BASE_URL}/admin/batch-tiffins`, {
            method: 'POST',
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                base_tiffin: baseTiffin,
                user_groups: userGroups
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.detail || 'Failed to create batch tiffins');
                });
            }
            return response.json();
        })
        .then(result => {
            showNotification(`Batch tiffins created successfully: ${result.message}`, 'success');

            document.getElementById('batch-tiffin-date').value = '';
            document.getElementById('batch-tiffin-time').value = '';
            document.getElementById('batch-tiffin-description').value = '';
            document.getElementById('batch-tiffin-price').value = '';
            document.getElementById('batch-tiffin-cancellation').value = '';

            resetUserGroups();

            document.querySelector('.tab-btn[data-tab="manage-tiffin"]').click();

            loadExistingTiffins();
        })
        .catch(error => {
            console.error('Error creating batch tiffins:', error);
            showNotification(error.message, 'error');
        })
        .finally(() => {
            batchCreateBtn.disabled = false;
            batchCreateBtn.textContent = 'Create Batch Tiffins';
        });

    } catch (error) {
        console.error('Error creating batch tiffins:', error);
        showNotification(error.message, 'error');

        const batchCreateBtn = document.getElementById('batch-create-btn');
        if (batchCreateBtn) {
            batchCreateBtn.disabled = false;
            batchCreateBtn.textContent = 'Create Batch Tiffins';
        }
    }
}

// Fix the loadUsersForSelect function
async function loadUsersForSelect() {
    try {
        console.log("Loading users for select dropdowns");

        // Use the apiRequest helper function
        const response = await apiRequest('/admin/users');
        
        console.log("Users response:", response);
        
        // Handle the response structure correctly
        const users = response.users || [];
        
        console.log(`Loaded ${users.length} users for select`);

        const activeUsers = users
            .filter(user => user.active)
            .sort((a, b) => a.name.localeCompare(b.name));

        // Populate the single tiffin user dropdown
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

        // Populate all user group selects
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

        console.log("Users loaded into dropdowns successfully");
        return true;
    } catch (error) {
        console.error('Error loading users for select:', error);
        showNotification('Failed to load users for dropdown: ' + error.message, 'error');
        return false;
    }
}
async function loadExistingTiffins(filters = {}, page = 1, limit = 9) {
    try {
        console.log("Loading existing tiffins with filters:", filters);

        const queryParams = [];
        if (filters.date) queryParams.push(`date=${filters.date}`);
        if (filters.status) queryParams.push(`status=${filters.status}`);
        if (filters.time) queryParams.push(`time=${filters.time}`);
        if (filters.user_id) queryParams.push(`user_id=${filters.user_id}`);
        
        // Add pagination parameters
        queryParams.push(`skip=${(page - 1) * limit}`);
        queryParams.push(`limit=${limit}`);

        const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';

        const tiffinsList = document.getElementById('manage-tiffins-list');
        if (tiffinsList) {
            tiffinsList.innerHTML = `
                <div class="loading-state">
                    <span class="spinner"></span>
                    <p>Loading tiffins...</p>
                </div>
            `;
        }

        const response = await apiRequest(`/admin/tiffins${queryString}`);

        console.log("Existing tiffins response:", response);

        const tiffins = response.data || [];
        const totalTiffins = response.total || 0;
        console.log(`Loaded ${tiffins.length} existing tiffins out of ${totalTiffins} total`);

        if (!tiffinsList) {
            console.error("Tiffins list element not found");
            return;
        }

        if (tiffins.length === 0) {
            tiffinsList.innerHTML = `
                <div class="empty-state">
                    <img src="empty.svg" alt="No tiffins">
                    <p>No tiffins found</p>
                </div>
            `;
            return;
        }

        // Collect all unique user IDs from all tiffins
        const allUserIds = new Set();
        tiffins.forEach(tiffin => {
            if (tiffin.assigned_users && tiffin.assigned_users.length > 0) {
                allUserIds.add(tiffin.assigned_users[0]);
            }
        });
        
        // Fetch all needed users in one batch
        const usersBatch = await fetchUsersBatch(Array.from(allUserIds));

        let tiffinsHTML = '';

        // Create tiffin cards HTML as before
        for (const tiffin of tiffins) {
            const statusClass = `status-${tiffin.status}`;
            const assignedUsers = tiffin.assigned_users.length;

            let userSample = '';
            if (assignedUsers > 0) {
                const firstUserId = tiffin.assigned_users[0];
                const userDetails = usersBatch[firstUserId];
                if (userDetails && userDetails.name) {
                    userSample = ` - ${userDetails.name}${assignedUsers > 1 ? ` +${assignedUsers-1} more` : ''}`;
                }
            }

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
                            <span class="tiffin-users">Users: ${assignedUsers}${userSample}</span>
                            <span class="tiffin-price">₹${tiffin.price.toFixed(2)}</span>
                        </div>
                        <button class="action-button manage-tiffin-btn">Manage</button>
                    </div>
                </div>
            `;
        }

        // Add pagination controls
        const totalPages = Math.ceil(totalTiffins / limit);
        let paginationHTML = '';
        
        if (totalPages > 1) {
            paginationHTML = '<div class="pagination-controls">';
            
            if (page > 1) {
                paginationHTML += `<button class="pagination-btn" data-page="${page-1}">Previous</button>`;
            }
            
            // Show page numbers
            const startPage = Math.max(1, page - 2);
            const endPage = Math.min(totalPages, page + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                paginationHTML += `<button class="pagination-btn ${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
            }
            
            if (page < totalPages) {
                paginationHTML += `<button class="pagination-btn" data-page="${page+1}">Next</button>`;
            }
            
            paginationHTML += '</div>';
        }

        tiffinsList.innerHTML = tiffinsHTML + paginationHTML;

        // Add event listeners for manage buttons
        document.querySelectorAll('.manage-tiffin-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const tiffinId = e.target.closest('.tiffin-card').dataset.tiffinId;
                showTiffinDetails(tiffinId);
            });
        });

        // Add event listeners for pagination buttons
        document.querySelectorAll('.pagination-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const pageNum = parseInt(btn.dataset.page);
                loadExistingTiffins(filters, pageNum, limit);
            });
        });

    } catch (error) {
        console.error('Error loading existing tiffins:', error);
        const tiffinsList = document.getElementById('manage-tiffins-list');
        if (tiffinsList) {
            tiffinsList.innerHTML = `
                <div class="empty-state">
                    <p>Error loading tiffins: ${error.message}</p>
                </div>
            `;
        }
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
    const basePriceInput = document.getElementById('batch-tiffin-price');
    const basePrice = basePriceInput ? basePriceInput.value : '';

    const groupDiv = document.createElement('div');
    groupDiv.className = 'user-group';
    groupDiv.innerHTML = `
        <h4>Group ${groupCount}</h4>
        <div class="user-group-select">
            <select class="user-group-select-input" multiple>
                <!-- Users will be loaded here -->
            </select>
        </div>
        <div class="form-group">
            <label for="group-${groupCount}-price">Price for this group (₹)</label>
            <input type="number" class="group-price-input" id="group-${groupCount}-price" value="${basePrice}" min="0" step="0.01">
        </div>
        <button type="button" class="secondary-button remove-group-btn">Remove Group</button>
    `;

    container.insertBefore(groupDiv, addGroupBtn);

    const removeBtn = groupDiv.querySelector('.remove-group-btn');
    if (removeBtn) {
        removeBtn.addEventListener('click', () => {
            container.removeChild(groupDiv);

            // Renumber the remaining groups
            container.querySelectorAll('.user-group').forEach((group, index) => {
                const groupHeading = group.querySelector('h4');
                if (groupHeading) {
                    groupHeading.textContent = `Group ${index + 1}`;
                }
            });
        });
    }

    // Get the select element for the new group
    const select = groupDiv.querySelector('.user-group-select-input');
    if (select) {
        // Load users for this new select
        apiRequest('/admin/users')
            .then(response => {
                // Handle the response structure correctly
                const users = response.users || [];
                
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
                console.error('Error loading users for new group:', error);
                showNotification('Failed to load users for the new group', 'error');
            });
    }
}

function resetUserGroups() {
    const container = document.getElementById('user-groups-container');
    if (container) {
        const basePriceInput = document.getElementById('batch-tiffin-price');
        const basePrice = basePriceInput ? basePriceInput.value : '';
        
        container.innerHTML = `
            <div class="user-group">
                <h4>Group 1</h4>
                <div class="user-group-select">
                    <select class="user-group-select-input" multiple>
                        <!-- Users will be loaded here -->
                    </select>
                </div>
                <div class="form-group">
                    <label for="group-1-price">Price for this group (₹)</label>
                    <input type="number" class="group-price-input" id="group-1-price" value="${basePrice}" min="0" step="0.01">
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

        // This will load users for the first group
        loadUsersForSelect();

        // Add event listener to the "Add Another Group" button
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

        let userName = request.user_id;
        try {
            if (request.user_details && request.user_details.name) {
                userName = request.user_details.name;
            } else {
                const userDetails = await apiRequest(`/admin/users/${request.user_id}`);
                if (userDetails && userDetails.name) {
                    userName = userDetails.name;
                }
            }
        } catch (error) {
            console.warn(`Couldn't fetch name for user ${request.user_id}:`, error);
        }

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
                        <label>Request from: ${userName} (${request.user_id})</label>
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
                        <input type="time" id="approve-cancellation" value="${request.preferred_time === 'morning' ? '07:00' : '17:00'}" required>
                    </div>
                    <button id="submit-approval" class="action-button">Approve Request</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        modal.querySelector('.close-modal').addEventListener('click', () => {
            document.body.removeChild(modal);
        });

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

                loadPendingRequests();

            } catch (error) {
                console.error('Error rejecting request:', error);
                showNotification(error.message, 'error');
            }
        }
    );
}

async function loadNoticesPolls() {
    if (userRole !== 'admin') return;

    console.log("Loading notices and polls admin page");

    loadAdminNotices();
    loadAdminPolls();
}

async function loadAdminNotices() {
    try {
        console.log("Loading admin notices with API key:", apiKey ? "Present" : "Missing");

        const response = await apiRequest('/admin/notices');
        console.log(`Loaded ${response?.length || 0} notices`);

        // Make sure we have an array to work with
        const notices = Array.isArray(response) ? response : 
                       (Array.isArray(response?.data) ? response.data : []);

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

        // Now sort the array safely
        notices.sort((a, b) => {
            const dateA = new Date(a.created_at || 0);
            const dateB = new Date(b.created_at || 0);
            return dateB - dateA;
        });

        let noticesHTML = '';

        notices.forEach(notice => {
            const priorityClass = notice.priority === 0 ? 'normal' : notice.priority === 1 ? 'important' : 'urgent';
            const priorityText = notice.priority === 0 ? 'Normal' : notice.priority === 1 ? 'Important' : 'Urgent';

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

        document.getElementById('notice-title').value = '';
        document.getElementById('notice-content').value = '';
        document.getElementById('notice-priority').value = '0';
        document.getElementById('notice-expires').value = '';

        loadAdminNotices();

    } catch (error) {
        console.error('Error creating notice:', error);
        showNotification(error.message, 'error');
    }
}

async function loadAdminPolls() {
    try {
        console.log("Loading admin polls with API key:", apiKey ? "Present" : "Missing");

        const response = await apiRequest('/admin/polls');
        console.log(`Loaded ${response?.length || 0} admin polls`);

        // Make sure we have an array to work with
        const polls = Array.isArray(response) ? response : 
                     (Array.isArray(response?.data) ? response.data : []);

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

        // Now sort the array safely
        polls.sort((a, b) => {
            const dateA = new Date(a.end_date || 0);
            const dateB = new Date(b.end_date || 0);
            return dateA - dateB;
        });

        let pollsHTML = '';

        for (const poll of polls) {
            let optionsHTML = '';

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

        document.querySelectorAll('.delete-poll-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const pollId = e.target.closest('.poll-card').dataset.pollId;
                deletePoll(pollId);
            });
        });

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

    const removeBtn = optionDiv.querySelector('.remove-option-btn');
    if (removeBtn) {
        removeBtn.addEventListener('click', function() {
            optionsContainer.removeChild(optionDiv);
        });
    }

    const newInput = optionDiv.querySelector('.poll-option');
    if (newInput) {
        newInput.focus();
    }
}

function setupPollCreationModal() {

    const optionsContainer = document.getElementById('poll-options-container');
    if (optionsContainer) {
        optionsContainer.innerHTML = '';

        addPollOption();
        addPollOption();
    }

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

    const addOptionBtn = document.getElementById('add-poll-option');
    if (addOptionBtn) {

        const newAddOptionBtn = addOptionBtn.cloneNode(true);
        if (addOptionBtn.parentNode) {
            addOptionBtn.parentNode.replaceChild(newAddOptionBtn, addOptionBtn);
        }

        newAddOptionBtn.addEventListener('click', addPollOption);
    }

    const submitPollBtn = document.getElementById('submit-poll');
    if (submitPollBtn) {

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

        document.getElementById('poll-question').value = '';
        document.getElementById('poll-start-date').value = '';
        document.getElementById('poll-end-date').value = '';

        const optionsContainer = document.getElementById('poll-options-container');
        if (optionsContainer) {
            optionsContainer.innerHTML = '';
            addPollOption();
            addPollOption();
        }

        loadAdminPolls();

    } catch (error) {
        console.error('Error creating poll:', error);
        showNotification('Failed to create poll: ' + error.message, 'error');
    }
}

async function loadGenerateInvoices() {
    if (userRole !== 'admin') return;

    console.log("Loading generate invoices page");

    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().split('T')[0];

    document.getElementById('invoice-start-date').value = firstDay;
    document.getElementById('invoice-end-date').value = lastDay;

    await loadAdminInvoices();

    const generateBtn = document.getElementById('generate-invoices-btn');
    if (generateBtn) {

        const newGenerateBtn = generateBtn.cloneNode(true);
        if (generateBtn.parentNode) {
            generateBtn.parentNode.replaceChild(newGenerateBtn, generateBtn);
        }

        newGenerateBtn.addEventListener('click', generateInvoices);
    }
}

async function loadAdminInvoices(filters = {}, page = 1, limit = 9) {
    try {
        console.log("Loading admin invoices with filters:", filters);

        const invoicesList = document.getElementById('admin-invoices-list');
        if (invoicesList) {
            invoicesList.innerHTML = `
                <div class="loading-state">
                    <span class="spinner"></span>
                    <p>Loading invoices...</p>
                </div>
            `;
        }

        const queryParams = [];
        if (filters.user_id) queryParams.push(`user_id=${encodeURIComponent(filters.user_id)}`);
        if (filters.paid !== undefined) queryParams.push(`paid=${filters.paid}`);
        if (filters.start_date) queryParams.push(`start_date=${encodeURIComponent(filters.start_date)}`);
        if (filters.end_date) queryParams.push(`end_date=${encodeURIComponent(filters.end_date)}`);
        
        // Add pagination parameters
        queryParams.push(`skip=${(page - 1) * limit}`);
        queryParams.push(`limit=${limit}`);

        const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';

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

        const result = await response.json();
        console.log("Admin invoices loaded:", result);
        
        const invoices = result.data || [];
        const totalItems = result.total || 0;

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
                        <div class="invoice-actions">
                            ${!invoice.paid ? `
                            <button class="action-button mark-paid-btn" data-invoice-id="${invoice._id}">
                                Mark as Paid
                            </button>
                            ` : ''}
                            <button class="warning-button delete-invoice-btn" data-invoice-id="${invoice._id}">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            `;
        });

        // Add pagination controls
        let paginationHTML = '';
        if (totalItems > 0) {
            const totalPages = Math.ceil(totalItems / limit);
            
            if (totalPages > 1) {
                paginationHTML = '<div class="pagination-controls">';
                
                if (page > 1) {
                    paginationHTML += `<button class="pagination-btn" data-page="${page-1}">Previous</button>`;
                }
                
                // Show page numbers
                const startPage = Math.max(1, page - 2);
                const endPage = Math.min(totalPages, page + 2);
                
                for (let i = startPage; i <= endPage; i++) {
                    paginationHTML += `<button class="pagination-btn ${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
                }
                
                if (page < totalPages) {
                    paginationHTML += `<button class="pagination-btn" data-page="${page+1}">Next</button>`;
                }
                
                paginationHTML += '</div>';
            }
        }

        invoicesList.innerHTML = invoicesHTML + paginationHTML;

        document.querySelectorAll('.mark-paid-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const invoiceId = e.target.dataset.invoiceId;
                markInvoicePaid(invoiceId);
            });
        });

        document.querySelectorAll('.delete-invoice-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const invoiceId = e.target.dataset.invoiceId;
                deleteInvoice(invoiceId);
            });
        });

        // Add event listeners for pagination buttons
        document.querySelectorAll('.pagination-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const pageNum = parseInt(btn.dataset.page);
                loadAdminInvoices(filters, pageNum, limit);
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

async function deleteInvoice(invoiceId) {
    if (!invoiceId) {
        showNotification('Invalid invoice ID', 'error');
        return;
    }

    showConfirmDialog(
        'Delete Invoice',
        'Are you sure you want to delete this invoice? This action cannot be undone.',
        async () => {
            try {
                console.log(`Deleting invoice: ${invoiceId}`);

                const result = await apiRequest(`/admin/invoices/${invoiceId}`, {
                    method: 'DELETE'
                });

                console.log("Delete invoice result:", result);

                showNotification('Invoice deleted successfully', 'success');

                loadAdminInvoices();

            } catch (error) {
                console.error('Error deleting invoice:', error);
                showNotification('Failed to delete invoice: ' + error.message, 'error');
            }
        }
    );
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

        const generateBtn = document.getElementById('generate-invoices-btn');
        if (generateBtn) {
            generateBtn.disabled = true;
            generateBtn.innerHTML = '<span class="spinner"></span> Generating...';
        }

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

        if (generateBtn) {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate Invoices';
        }

        setTimeout(() => {
            loadAdminInvoices();
        }, 1500); 

    } catch (error) {
        console.error('Error generating invoices:', error);
        showNotification('Failed to generate invoices: ' + error.message, 'error');

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

                loadAdminInvoices();

            } catch (error) {
                console.error('Error marking invoice as paid:', error);
                showNotification('Failed to mark invoice as paid: ' + error.message, 'error');
            }
        }
    );
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

        document.getElementById('request-description').value = '';
        document.getElementById('request-date').value = '';
        document.getElementById('request-time').value = '';
        document.getElementById('request-instructions').value = '';

    } catch (error) {
        console.error('Error submitting tiffin request:', error);
        showNotification('Failed to submit request: ' + error.message, 'error');
    }
}

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

function formatTiffinTime(timeStr) {
    if (!timeStr) return 'N/A';

    const timeMap = {
        'morning': 'Morning (8:00 AM)',
        'evening': 'Evening (6:00 PM)'
    };

    return timeMap[timeStr] || timeStr;
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

function showNotification(message, type = 'info') {
    const toast = document.getElementById('notification-toast');
    const toastMessage = document.getElementById('notification-toast-message');

    if (!toast || !toastMessage) {
        console.error("Notification elements not found");
        return;
    }

    toastMessage.textContent = message;

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

    toast.classList.remove('active');

    void toast.offsetWidth;

    toast.classList.add('active');

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

    modal.classList.add('active');

    const closeModal = () => {
        modal.classList.remove('active');
    };

    const newYesBtn = yesBtn.cloneNode(true);
    yesBtn.parentNode.replaceChild(newYesBtn, yesBtn);

    const newNoBtn = noBtn.cloneNode(true);
    noBtn.parentNode.replaceChild(newNoBtn, noBtn);

    const newCloseBtn = modal.querySelector('.close-modal').cloneNode(true);
    modal.querySelector('.close-modal').parentNode.replaceChild(
        newCloseBtn, 
        modal.querySelector('.close-modal')
    );

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

function setupEventListeners() {

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

    const tiffinTabBtns = document.querySelectorAll('.tiffin-management-tabs .tab-btn');
    tiffinTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            console.log('Tiffin tab clicked:', this.getAttribute('data-tab'));

            document.querySelectorAll('.tiffin-management-tabs .tab-btn').forEach(tab => {
                tab.classList.remove('active');
            });

            this.classList.add('active');

            document.querySelectorAll('#manage-tiffins-page .tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });

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

    document.getElementById('login-btn').addEventListener('click', async () => {
        const userId = document.getElementById('login-userid').value.trim();
        const password = document.getElementById('login-password').value;

        if (!userId || !password) {
            document.getElementById('login-message').textContent = 'Please enter both user ID and password';
            return;
        }

        document.getElementById('login-btn').innerHTML = '<span class="spinner"></span> Logging in...';
        document.getElementById('login-btn').disabled = true;

        try {
            const success = await login(userId, password);
            if (!success) {
                document.getElementById('login-message').textContent = 'Invalid credentials. Please try again.';
            }
        } finally {

            document.getElementById('login-btn').innerHTML = 'Login';
            document.getElementById('login-btn').disabled = false;
        }
    });

    document.getElementById('register-btn').addEventListener('click', () => {
        document.getElementById('register-message').textContent = 'Registration is disabled. Please contact an administrator.';
    });

    document.getElementById('logout-btn').addEventListener('click', logout);

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

    document.getElementById('toggle-sidebar').addEventListener('click', () => {
        document.querySelector('.sidebar').classList.toggle('active');
    });

    document.getElementById('theme-toggle-btn').addEventListener('click', toggleTheme);

    document.getElementById('save-profile').addEventListener('click', updateUserProfile);

    document.getElementById('change-password').addEventListener('click', changePassword);

    document.getElementById('apply-tiffin-filter').addEventListener('click', () => {
        const date = document.getElementById('tiffin-date-filter').value;
        const time = document.getElementById('tiffin-time-filter').value;
        const status = document.getElementById('tiffin-status-filter').value;

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

    document.getElementById('apply-history-filter').addEventListener('click', () => {
        const startDate = document.getElementById('history-start-date').value;
        const endDate = document.getElementById('history-end-date').value;

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

    document.getElementById('add-notice-btn').addEventListener('click', () => {
        document.getElementById('create-notice-modal').classList.add('active');
    });

    document.querySelector('#create-notice-modal .close-modal').addEventListener('click', () => {
        document.getElementById('create-notice-modal').classList.remove('active');
    });

    document.getElementById('submit-notice').addEventListener('click', createNotice);

    document.getElementById('add-poll-btn').addEventListener('click', function() {
        setupPollCreationModal();
        document.getElementById('create-poll-modal').classList.add('active');
    });

    document.querySelector('#create-poll-modal .close-modal').addEventListener('click', () => {
        document.getElementById('create-poll-modal').classList.remove('active');
    });

    document.getElementById('add-poll-option').addEventListener('click', addPollOption);
    document.getElementById('submit-poll').addEventListener('click', createPoll);

    document.getElementById('generate-invoices-btn').addEventListener('click', generateInvoices);
    document.getElementById('user-search').addEventListener('input', (e) => {
        const searchQuery = e.target.value.trim();
        loadManageUsers(1, 10, searchQuery);  // Use loadManageUsers with pagination and search
    });
    
    document.getElementById('add-user-btn').addEventListener('click', () => {
        document.getElementById('add-user-modal').classList.add('active');
    });

    document.querySelector('#add-user-modal .close-modal').addEventListener('click', () => {
        document.getElementById('add-user-modal').classList.remove('active');
    });

    document.getElementById('submit-new-user').addEventListener('click', createUser);

    document.getElementById('request-tiffin-btn').addEventListener('click', () => {
        document.getElementById('request-tiffin-modal').classList.add('active');
    });

    document.querySelector('#request-tiffin-modal .close-modal').addEventListener('click', () => {
        document.getElementById('request-tiffin-modal').classList.remove('active');
    });

    document.getElementById('submit-request').addEventListener('click', submitTiffinRequest);

    document.getElementById('create-tiffin-btn').addEventListener('click', createTiffinWithoutMenuItems);

    document.getElementById('batch-create-btn').addEventListener('click', batchCreateTiffinsWithoutMenuItems);

    document.getElementById('add-user-group').addEventListener('click', addUserGroup);

    document.getElementById('notifications-btn').addEventListener('click', () => {
        document.getElementById('notification-dropdown').classList.toggle('active');
    });

    document.addEventListener('click', (e) => {
        const dropdown = document.getElementById('notification-dropdown');
        const btn = document.getElementById('notifications-btn');

        if (dropdown.classList.contains('active') && 
            !dropdown.contains(e.target) && 
            !btn.contains(e.target)) {
            dropdown.classList.remove('active');
        }
    });

    document.getElementById('mark-all-read').addEventListener('click', markAllNotificationsRead);

    document.querySelectorAll('.quick-action-card').forEach(card => {
        card.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = card.getAttribute('data-page');
            if (pageId) {
                navigateTo(pageId);
            }
        });
    });

}
