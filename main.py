from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, errors
from datetime import datetime, timedelta
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from bson import ObjectId
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
import time

# Load environment variables
load_dotenv()

# Configuration
class Config:
    MONGO_URI = os.getenv('MONGO_URI')
    JWT_SECRET = os.getenv('JWT_SECRET')
    ADMIN_ID = os.getenv('ADMIN_ID')
    ADMIN_PHONE = os.getenv('ADMIN_PHONE')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
    LOG_FOLDER = 'logs'
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # seconds

# Application setup
app = Flask(__name__)
CORS(app)

# Logging setup
def setup_logging():
    if not os.path.exists(Config.LOG_FOLDER):
        os.mkdir(Config.LOG_FOLDER)
    file_handler = RotatingFileHandler(
        f'{Config.LOG_FOLDER}/tiffin_treats.log',
        maxBytes=10240,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Tiffin Treats startup')

setup_logging()

# MongoDB connection with retry mechanism
def get_db():
    retries = 0
    while retries < Config.MAX_RETRIES:
        try:
            client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')  # Test connection
            return client.tiffin_treats
        except errors.ServerSelectionTimeoutError:
            retries += 1
            if retries == Config.MAX_RETRIES:
                app.logger.error("Failed to connect to MongoDB after multiple retries")
                raise
            time.sleep(Config.RETRY_DELAY)

# Initialize admin user
def init_admin():
    try:
        db = get_db()
        if not db.users.find_one({'role': 'admin'}):
            password = Config.ADMIN_PASSWORD
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
            
            admin = {
                'user_id': Config.ADMIN_ID,
                'phone': Config.ADMIN_PHONE,
                'password': hashed_password,
                'role': 'admin',
                'created_at': datetime.utcnow()
            }
            db.users.insert_one(admin)
            app.logger.info("Admin user initialized successfully")
    except Exception as e:
        app.logger.error(f"Error initializing admin user: {str(e)}")
        raise

init_admin()

# Error handling
def handle_errors(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except errors.PyMongoError as e:
            app.logger.error(f"Database error: {str(e)}")
            return jsonify({'error': 'Database error occurred'}), 500
        except Exception as e:
            app.logger.error(f"Unexpected error: {str(e)}")
            return jsonify({'error': 'An unexpected error occurred'}), 500
    return decorated

# Authentication decorator with error handling
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
            request.user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            app.logger.error(f"Authentication error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401
    return decorated

# Admin decorator with error handling
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
            if payload['role'] != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            request.user = payload
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Admin authentication error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401
    return decorated

# Authentication routes
@app.route('/login', methods=['POST'])
@handle_errors
def login():
    try:
        data = request.get_json()
        app.logger.debug(f"Received data: {data}")  # Debug log
        
        user_id = data.get('user_id')
        password = data.get('password')
        
        app.logger.info(f"Login attempt for user_id: {user_id}")
        
        if not user_id or not password:
            return jsonify({'error': 'Missing credentials'}), 400
        
        db = get_db()
        user = db.users.find_one({'user_id': user_id})
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        try:
            # Convert password to bytes for comparison
            password_bytes = password.encode('utf-8')
            stored_password = user['password']

            # If stored password is string, convert to bytes
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')

            # Check password
            if bcrypt.checkpw(password_bytes, stored_password):
                token = jwt.encode({
                    'user_id': user['user_id'],
                    'role': user['role'],
                    'exp': datetime.utcnow() + timedelta(days=1)
                }, Config.JWT_SECRET)

                # Ensure token is string
                if isinstance(token, bytes):
                    token = token.decode('utf-8')

                return jsonify({
                    'token': token,
                    'role': user['role'],
                    'user_id': user['user_id']
                })
            else:
                return jsonify({'error': 'Invalid credentials'}), 401

        except Exception as e:
            app.logger.error(f"Password comparison error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/create-test-user', methods=['POST'])
def create_test_user():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        password = data.get('password')
        
        if not user_id or not password:
            return jsonify({'error': 'Missing user_id or password'}), 400
            
        db = get_db()
        
        # Check if user already exists
        existing_user = db.users.find_one({'user_id': user_id})
        if existing_user:
            return jsonify({'error': 'User already exists'}), 400
            
        # Hash password
        password_bytes = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        
        # Create user
        user = {
            'user_id': user_id,
            'password': hashed_password,
            'role': 'user',
            'phone': '1234567890',  # Default phone
            'created_at': datetime.utcnow()
        }
        
        db.users.insert_one(user)
        
        return jsonify({'message': 'Test user created successfully'})
        
    except Exception as e:
        app.logger.error(f"Error creating test user: {str(e)}")
        return jsonify({'error': str(e)}), 500

# User management routes
@app.route('/users', methods=['POST'])
@admin_required
@handle_errors
def create_user():
    try:
        data = request.get_json()
        required_fields = ['user_id', 'phone', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        db = get_db()
        if db.users.find_one({'user_id': data['user_id']}):
            return jsonify({'error': 'User ID already exists'}), 400
        
        # Ensure password is string and encode it
        password = str(data['password']).encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        user = {
            'user_id': data['user_id'],
            'phone': data['phone'],
            'password': hashed_password,
            'role': 'user',
            'delivery_address': data.get('delivery_address', ''),
            'created_at': datetime.utcnow()
        }
        
        db.users.insert_one(user)
        app.logger.info(f"User created successfully: {data['user_id']}")
        return jsonify({'message': 'User created successfully'})
    
    except Exception as e:
        app.logger.error(f"Error creating user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/users/<user_id>', methods=['PUT'])
@auth_required
@handle_errors
def update_user(user_id):
    if request.user['role'] != 'admin' and request.user['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No update data provided'}), 400
    
    update_data = {}
    if 'delivery_address' in data:
        update_data['delivery_address'] = data['delivery_address']
    
    if update_data:
        db = get_db()
        result = db.users.update_one(
            {'user_id': user_id},
            {'$set': update_data}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'message': 'User updated successfully'})

@app.route('/users', methods=['GET'])
@admin_required
@handle_errors
def get_users():
    db = get_db()
    users = list(db.users.find({'role': 'user'}, {'password': 0}))
    return jsonify({'users': users})

# Tiffin management routes
@app.route('/tiffins', methods=['POST'])
@admin_required
@handle_errors
def create_tiffin():
    data = request.get_json()
    required_fields = ['name', 'description', 'price', 'date', 'time_slot', 'cancellation_time']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        tiffin = {
            'name': data['name'],
            'description': data['description'],
            'price': float(data['price']),
            'date': datetime.strptime(data['date'], '%Y-%m-%d'),
            'time_slot': data['time_slot'],
            'cancellation_time': datetime.strptime(data['cancellation_time'], '%Y-%m-%d %H:%M'),
            'max_capacity': int(data.get('max_capacity', 0)),
            'assigned_users': [],
            'status': 'preparing',
            'created_at': datetime.utcnow()
        }
    except ValueError:
        return jsonify({'error': 'Invalid date format or numeric value'}), 400
    
    db = get_db()
    db.tiffins.insert_one(tiffin)
    return jsonify({'message': 'Tiffin created successfully'})

@app.route('/tiffins/<tiffin_id>/status', methods=['PUT'])
@admin_required
@handle_errors
def update_tiffin_status(tiffin_id):
    data = request.get_json()
    if 'status' not in data:
        return jsonify({'error': 'Status not provided'}), 400
    
    try:
        db = get_db()
        result = db.tiffins.update_one(
            {'_id': ObjectId(tiffin_id)},
            {'$set': {'status': data['status']}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Tiffin not found'}), 404
    except Exception as e:
        app.logger.error(f"Error updating tiffin status: {str(e)}")
        return jsonify({'error': 'Invalid tiffin ID'}), 400
    
    return jsonify({'message': 'Tiffin status updated'})

@app.route('/tiffins/upcoming', methods=['GET'])
@auth_required
@handle_errors
def get_upcoming_tiffins():
    db = get_db()
    tiffins = list(db.tiffins.find({
        'date': {'$gte': datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)}
    }).sort('date', 1))
    return jsonify({'tiffins': tiffins})

@app.route('/tiffins/<tiffin_id>/cancel', methods=['POST'])
@auth_required
@handle_errors
def cancel_tiffin(tiffin_id):
    try:
        db = get_db()
        tiffin = db.tiffins.find_one({'_id': ObjectId(tiffin_id)})
        if not tiffin:
            return jsonify({'error': 'Tiffin not found'}), 404
        
        if datetime.utcnow() > tiffin['cancellation_time']:
            return jsonify({'error': 'Cancellation time has passed'}), 400
        
        result = db.tiffins.update_one(
            {'_id': ObjectId(tiffin_id)},
            {'$pull': {'assigned_users': request.user['user_id']}}
        )
        if result.modified_count == 0:
            return jsonify({'error': 'User not assigned to this tiffin'}), 400
    except Exception as e:
        app.logger.error(f"Error cancelling tiffin: {str(e)}")
        return jsonify({'error': 'Invalid tiffin ID'}), 400
    
    return jsonify({'message': 'Tiffin cancelled successfully'})

# History routes
@app.route('/history', methods=['GET'])
@auth_required
@handle_errors
def get_history():
    db = get_db()
    history = list(db.tiffins.find({
        'assigned_users': request.user['user_id'],
        'date': {'$lt': datetime.utcnow()}
    }).sort('date', -1))
    return jsonify({'history': history})

# Invoice routes
@app.route('/invoices', methods=['GET'])
@auth_required
@handle_errors
def get_invoices():
    user_id = request.user['user_id']
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = {'assigned_users': user_id}
    if start_date and end_date:
        try:
            query['date'] = {
                '$gte': datetime.strptime(start_date, '%Y-%m-%d'),
                '$lte': datetime.strptime(end_date, '%Y-%m-%d')
            }
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
    
    db = get_db()
    tiffins = list(db.tiffins.find(query))
    total_amount = sum(tiffin['price'] for tiffin in tiffins)
    
    return jsonify({
        'tiffins': tiffins,
        'total_amount': total_amount
    })

# Notice routes
@app.route('/notices', methods=['POST'])
@admin_required
@handle_errors
def create_notice():
    data = request.get_json()
    if not all(field in data for field in ['title', 'content']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    notice = {
        'title': data['title'],
        'content': data['content'],
        'created_at': datetime.utcnow()
    }
    db = get_db()
    db.notices.insert_one(notice)
    return jsonify({'message': 'Notice created successfully'})

@app.route('/notices', methods=['GET'])
@auth_required
@handle_errors
def get_notices():
    db = get_db()
    notices = list(db.notices.find().sort('created_at', -1))
    return jsonify({'notices': notices})

# Poll routes
@app.route('/polls', methods=['POST'])
@admin_required
@handle_errors
def create_poll():
    data = request.get_json()
    required_fields = ['question', 'options', 'start_date', 'end_date']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        poll = {
            'question': data['question'],
            'options': data['options'],
            'start_date': datetime.strptime(data['start_date'], '%Y-%m-%d'),
            'end_date': datetime.strptime(data['end_date'], '%Y-%m-%d'),
            'votes': {option: [] for option in data['options']},
            'created_at': datetime.utcnow()
        }
        
        if poll['start_date'] > poll['end_date']:
            return jsonify({'error': 'End date must be after start date'}), 400
            
        db = get_db()
        db.polls.insert_one(poll)
        return jsonify({'message': 'Poll created successfully'})
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

@app.route('/polls/<poll_id>/vote', methods=['POST'])
@auth_required
@handle_errors
def vote_poll(poll_id):
    data = request.get_json()
    if 'option' not in data:
        return jsonify({'error': 'No option provided'}), 400
    
    try:
        db = get_db()
        poll = db.polls.find_one({'_id': ObjectId(poll_id)})
        
        if not poll:
            return jsonify({'error': 'Poll not found'}), 404
        
        current_time = datetime.utcnow()
        if current_time < poll['start_date']:
            return jsonify({'error': 'Poll has not started yet'}), 400
        if current_time > poll['end_date']:
            return jsonify({'error': 'Poll has ended'}), 400
            
        if data['option'] not in poll['options']:
            return jsonify({'error': 'Invalid option'}), 400
        
        # Remove previous vote if exists
        for option in poll['votes']:
            if request.user['user_id'] in poll['votes'][option]:
                poll['votes'][option].remove(request.user['user_id'])
        
        # Add new vote
        poll['votes'][data['option']].append(request.user['user_id'])
        
        db.polls.update_one(
            {'_id': ObjectId(poll_id)},
            {'$set': {'votes': poll['votes']}}
        )
        
        return jsonify({'message': 'Vote recorded successfully'})
    except Exception as e:
        app.logger.error(f"Error recording vote: {str(e)}")
        return jsonify({'error': 'Invalid poll ID'}), 400

@app.route('/polls/active', methods=['GET'])
@auth_required
@handle_errors
def get_active_polls():
    db = get_db()
    current_time = datetime.utcnow()
    polls = list(db.polls.find({
        'end_date': {'$gte': current_time},
        'start_date': {'$lte': current_time}
    }).sort('end_date', 1))
    return jsonify({'polls': polls})

# Special requests routes
@app.route('/requests', methods=['POST'])
@auth_required
@handle_errors
def create_request():
    data = request.get_json()
    if not all(field in data for field in ['description', 'date']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        special_request = {
            'user_id': request.user['user_id'],
            'description': data['description'],
            'date': datetime.strptime(data['date'], '%Y-%m-%d'),
            'status': 'pending',
            'created_at': datetime.utcnow()
        }
        
        db = get_db()
        db.special_requests.insert_one(special_request)
        return jsonify({'message': 'Request created successfully'})
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

@app.route('/requests', methods=['GET'])
@admin_required
@handle_errors
def get_requests():
    db = get_db()
    requests = list(db.special_requests.find().sort('created_at', -1))
    return jsonify({'requests': requests})

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    try:
        db = get_db()
        db.admin.command('ping')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow()
        })
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'timestamp': datetime.utcnow()
        }), 500

# Background scheduler setup
def create_scheduler():
    scheduler = BackgroundScheduler()
    
    def ping_server():
        try:
            requests.get('https://tiffintreats-20mb.onrender.com/health', timeout=5)
            app.logger.info("Keep-alive ping successful")
        except Exception as e:
            app.logger.error(f"Keep-alive ping failed: {str(e)}")
    
    scheduler.add_job(ping_server, 'interval', minutes=10)
    scheduler.start()
    app.logger.info("Background scheduler started")
    return scheduler

# Graceful shutdown handler
def shutdown_handler(signum, frame):
    app.logger.info("Received shutdown signal")
    scheduler.shutdown()
    app.logger.info("Scheduler shutdown complete")
    exit(0)

# Initialize scheduler
scheduler = create_scheduler()

if __name__ == '__main__':
    # Register shutdown handler
    import signal
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    
    # Start the application
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
