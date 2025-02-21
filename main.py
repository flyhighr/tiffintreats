from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import threading
import time
import requests
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
MONGO_URI = os.getenv('MONGO_URI')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
ADMIN_PHONE = os.getenv('ADMIN_PHONE')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ADMIN_ID = os.getenv('ADMIN_ID')

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client.tiffintreats

# Auth decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            current_user = db.users.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return jsonify({'message': 'Invalid token'}), 401
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split(' ')[1]
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            current_user = db.users.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user or current_user['role'] != 'admin':
                return jsonify({'message': 'Admin access required'}), 403
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Health check endpoint and self-ping
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200

def ping_server():
    while True:
        try:
            requests.get('https://your-render-url/health')
            time.sleep(600)  # 10 minutes
        except:
            pass

# Start ping thread
ping_thread = threading.Thread(target=ping_server)
ping_thread.daemon = True
ping_thread.start()

# Authentication routes
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_id = data.get('userId')
    phone = data.get('phone')
    password = data.get('password')

    user = None
    if user_id:
        user = db.users.find_one({'userId': user_id})
    elif phone:
        user = db.users.find_one({'phone': phone})

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Invalid password'}), 401

    token = jwt.encode({
        'user_id': str(user['_id']),
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(days=1)
    }, JWT_SECRET_KEY)

    return jsonify({
        'token': token,
        'role': user['role'],
        'userId': user['userId']
    }), 200

# Admin user management routes
@app.route('/admin/users', methods=['POST'])
@admin_required
def create_user(current_user):
    data = request.json
    
    # Check if user already exists
    if db.users.find_one({'phone': data['phone']}) or \
       db.users.find_one({'userId': data['userId']}):
        return jsonify({'message': 'User already exists'}), 400

    user_data = {
        'userId': data['userId'],
        'phone': data['phone'],
        'password': bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()),
        'name': data['name'],
        'address': data['address'],
        'role': 'user',
        'created_at': datetime.utcnow()
    }
    
    db.users.insert_one(user_data)
    return jsonify({'message': 'User created successfully'}), 201

# Tiffin management routes
@app.route('/admin/tiffins', methods=['POST'])
@admin_required
def create_tiffin(current_user):
    data = request.json
    tiffin_data = {
        'date': datetime.fromisoformat(data['date']),
        'type': data['type'],  # 'morning' or 'evening'
        'description': data['description'],
        'price': float(data['price']),
        'items': data['items'],
        'cancellation_time': datetime.fromisoformat(data['cancellation_time']),
        'delivery_time': datetime.fromisoformat(data['delivery_time']),
        'status': 'scheduled',
        'assigned_users': data.get('assigned_users', []),  # List of user IDs
        'created_at': datetime.utcnow()
    }
    
    db.tiffins.insert_one(tiffin_data)
    return jsonify({'message': 'Tiffin created successfully'}), 201

@app.route('/admin/tiffins/<tiffin_id>/status', methods=['PUT'])
@admin_required
def update_tiffin_status(current_user, tiffin_id):
    data = request.json
    new_status = data['status']
    valid_statuses = ['scheduled', 'preparing', 'prepared', 'out_for_delivery', 'delivered']
    
    if new_status not in valid_statuses:
        return jsonify({'message': 'Invalid status'}), 400
        
    db.tiffins.update_one(
        {'_id': ObjectId(tiffin_id)},
        {'$set': {'status': new_status}}
    )
    return jsonify({'message': 'Status updated successfully'}), 200

@app.route('/tiffins/cancel/<tiffin_id>', methods=['POST'])
@token_required
def cancel_tiffin(current_user, tiffin_id):
    tiffin = db.tiffins.find_one({'_id': ObjectId(tiffin_id)})
    if not tiffin:
        return jsonify({'message': 'Tiffin not found'}), 404
        
    # Check if user is assigned to this tiffin
    if current_user['userId'] not in tiffin['assigned_users']:
        return jsonify({'message': 'Not authorized'}), 403
        
    # Check cancellation time
    if datetime.utcnow() > tiffin['cancellation_time']:
        return jsonify({'message': 'Cancellation time has passed'}), 400
        
    # Record cancellation
    cancellation = {
        'tiffin_id': ObjectId(tiffin_id),
        'user_id': current_user['userId'],
        'cancelled_at': datetime.utcnow()
    }
    db.cancellations.insert_one(cancellation)
    
    # Remove user from assigned users
    db.tiffins.update_one(
        {'_id': ObjectId(tiffin_id)},
        {'$pull': {'assigned_users': current_user['userId']}}
    )
    
    return jsonify({'message': 'Tiffin cancelled successfully'}), 200

# Notice system routes
@app.route('/admin/notices', methods=['POST'])
@admin_required
def create_notice(current_user):
    data = request.json
    notice = {
        'title': data['title'],
        'content': data['content'],
        'priority': data.get('priority', 'normal'),
        'target_users': data.get('target_users', []),  # Empty list means all users
        'created_at': datetime.utcnow(),
        'expires_at': datetime.fromisoformat(data['expires_at']) if 'expires_at' in data else None
    }
    
    db.notices.insert_one(notice)
    return jsonify({'message': 'Notice created successfully'}), 201

@app.route('/notices', methods=['GET'])
@token_required
def get_notices(current_user):
    current_time = datetime.utcnow()
    notices = list(db.notices.find({
        '$or': [
            {'target_users': []},
            {'target_users': current_user['userId']}
        ],
        '$or': [
            {'expires_at': None},
            {'expires_at': {'$gt': current_time}}
        ]
    }).sort('created_at', -1))
    
    # Convert ObjectId to string for JSON serialization
    for notice in notices:
        notice['_id'] = str(notice['_id'])
    
    return jsonify(notices), 200

# Poll system routes
@app.route('/admin/polls', methods=['POST'])
@admin_required
def create_poll(current_user):
    data = request.json
    poll = {
        'title': data['title'],
        'description': data['description'],
        'options': data['options'],
        'start_date': datetime.fromisoformat(data['start_date']),
        'end_date': datetime.fromisoformat(data['end_date']),
        'created_at': datetime.utcnow(),
        'votes': {option: 0 for option in data['options']},
        'voters': []
    }
    
    db.polls.insert_one(poll)
    return jsonify({'message': 'Poll created successfully'}), 201

@app.route('/polls/<poll_id>/vote', methods=['POST'])
@token_required
def vote_poll(current_user, poll_id):
    data = request.json
    selected_option = data['option']
    
    poll = db.polls.find_one({'_id': ObjectId(poll_id)})
    if not poll:
        return jsonify({'message': 'Poll not found'}), 404
        
    if current_user['userId'] in poll['voters']:
        return jsonify({'message': 'Already voted'}), 400
        
    if datetime.utcnow() > poll['end_date']:
        return jsonify({'message': 'Poll has ended'}), 400
        
    if selected_option not in poll['options']:
        return jsonify({'message': 'Invalid option'}), 400
        
    db.polls.update_one(
        {'_id': ObjectId(poll_id)},
        {
            '$inc': {f'votes.{selected_option}': 1},
            '$push': {'voters': current_user['userId']}
        }
    )
    
    return jsonify({'message': 'Vote recorded successfully'}), 200

# Tiffin request routes
@app.route('/tiffin-requests', methods=['POST'])
@token_required
def create_tiffin_request(current_user):
    data = request.json
    request_data = {
        'user_id': current_user['userId'],
        'description': data['description'],
        'preferred_date': datetime.fromisoformat(data['preferred_date']),
        'status': 'pending',
        'created_at': datetime.utcnow()
    }
    
    db.tiffin_requests.insert_one(request_data)
    return jsonify({'message': 'Request submitted successfully'}), 201

# User profile management
@app.route('/user/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    user = db.users.find_one({'_id': current_user['_id']})
    user['_id'] = str(user['_id'])
    user.pop('password', None)  # Remove password from response
    return jsonify(user), 200

@app.route('/user/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.json
    allowed_updates = ['name', 'address']
    update_data = {k: v for k, v in data.items() if k in allowed_updates}
    
    db.users.update_one(
        {'_id': current_user['_id']},
        {'$set': update_data}
    )
    return jsonify({'message': 'Profile updated successfully'}), 200

# Tiffin history
@app.route('/user/history', methods=['GET'])
@token_required
def get_user_history(current_user):
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    history = list(db.tiffins.find(
        {'assigned_users': current_user['userId']},
        {'_id': 1, 'date': 1, 'type': 1, 'status': 1, 'price': 1, 'description': 1}
    ).sort('date', -1).skip((page-1)*per_page).limit(per_page))
    
    # Add cancellation information
    for item in history:
        item['_id'] = str(item['_id'])
        cancellation = db.cancellations.find_one({
            'tiffin_id': ObjectId(item['_id']),
            'user_id': current_user['userId']
        })
        item['cancelled'] = bool(cancellation)
        if cancellation:
            item['cancelled_at'] = cancellation['cancelled_at']
    
    total = db.tiffins.count_documents({'assigned_users': current_user['userId']})
    
    return jsonify({
        'history': history,
        'total': total,
        'pages': (total + per_page - 1) // per_page
    }), 200

# Invoice generation
@app.route('/user/invoices', methods=['GET'])
@token_required
def get_invoices(current_user):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = {'assigned_users': current_user['userId']}
    if start_date and end_date:
        query['date'] = {
            '$gte': datetime.fromisoformat(start_date),
            '$lte': datetime.fromisoformat(end_date)
        }
    
    tiffins = list(db.tiffins.find(query))
    
    # Calculate total amount
    total_amount = sum(tiffin['price'] for tiffin in tiffins 
                      if not db.cancellations.find_one({
                          'tiffin_id': tiffin['_id'],
                          'user_id': current_user['userId']
                      }))
    
    # Generate invoice details
    invoice_items = []
    for tiffin in tiffins:
        cancelled = db.cancellations.find_one({
            'tiffin_id': tiffin['_id'],
            'user_id': current_user['userId']
        })
        
        invoice_items.append({
            'date': tiffin['date'],
            'type': tiffin['type'],
            'description': tiffin['description'],
            'price': tiffin['price'],
            'status': 'Cancelled' if cancelled else tiffin['status']
        })
    
    invoice = {
        'user_id': current_user['userId'],
        'user_name': current_user['name'],
        'items': invoice_items,
        'total_amount': total_amount,
        'generated_at': datetime.utcnow()
    }
    
    return jsonify(invoice), 200

# Dashboard data
@app.route('/admin/dashboard', methods=['GET'])
@admin_required
def get_admin_dashboard(current_user):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Today's statistics
    today_tiffins = list(db.tiffins.find({'date': {'$gte': today}}))
    total_users = db.users.count_documents({'role': 'user'})
    active_users = len(set(sum([t['assigned_users'] for t in today_tiffins], [])))
    
    # Pending requests
    pending_requests = db.tiffin_requests.count_documents({'status': 'pending'})
    
    # Active polls
    active_polls = db.polls.count_documents({
        'end_date': {'$gt': datetime.utcnow()}
    })
    
    return jsonify({
        'today_tiffins': len(today_tiffins),
        'total_users': total_users,
        'active_users': active_users,
        'pending_requests': pending_requests,
        'active_polls': active_polls
    }), 200

@app.route('/user/dashboard', methods=['GET'])
@token_required
def get_user_dashboard(current_user):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Today's tiffins
    today_tiffins = list(db.tiffins.find({
        'date': {'$gte': today},
        'assigned_users': current_user['userId']
    }))
    
    # Active notices
    notices = list(db.notices.find({
        '$or': [
            {'target_users': []},
            {'target_users': current_user['userId']}
        ],
        '$or': [
            {'expires_at': None},
            {'expires_at': {'$gt': datetime.utcnow()}}
        ]
    }).limit(5))
    
    # Active polls
    polls = list(db.polls.find({
        'end_date': {'$gt': datetime.utcnow()},
        'voters': {'$nin': [current_user['userId']]}
    }))
    
    # Format response
    for tiffin in today_tiffins:
        tiffin['_id'] = str(tiffin['_id'])
    for notice in notices:
        notice['_id'] = str(notice['_id'])
    for poll in polls:
        poll['_id'] = str(poll['_id'])
    
    return jsonify({
        'today_tiffins': today_tiffins,
        'notices': notices,
        'polls': polls
    }), 200

# Utility endpoints
@app.route('/admin/settings', methods=['GET', 'PUT'])
@admin_required
def manage_settings(current_user):
    if request.method == 'GET':
        settings = db.settings.find_one({'type': 'global'})
        return jsonify(settings or {}), 200
    
    data = request.json
    db.settings.update_one(
        {'type': 'global'},
        {'$set': data},
        upsert=True
    )
    return jsonify({'message': 'Settings updated successfully'}), 200

if __name__ == '__main__':
    # Ensure indexes
    db.users.create_index('userId', unique=True)
    db.users.create_index('phone', unique=True)
    db.tiffins.create_index([('date', 1), ('type', 1)])
    db.notices.create_index('created_at')
    db.polls.create_index('end_date')
    
    app.run(debug=True)
