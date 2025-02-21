# main.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from bson import ObjectId

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
MONGO_URI = os.getenv('MONGO_URI')
JWT_SECRET = os.getenv('JWT_SECRET')
ADMIN_ID = os.getenv('ADMIN_ID')
ADMIN_PHONE = os.getenv('ADMIN_PHONE')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client.tiffin_treats

# Initialize admin user if not exists
def init_admin():
    if not db.users.find_one({'role': 'admin'}):
        hashed_password = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
        admin = {
            'user_id': ADMIN_ID,
            'phone': ADMIN_PHONE,
            'password': hashed_password,
            'role': 'admin',
            'created_at': datetime.utcnow()
        }
        db.users.insert_one(admin)

init_admin()

# Authentication decorator
def auth_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    decorated.__name__ = f.__name__
    return decorated

# Admin decorator
def admin_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if payload['role'] != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            request.user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    decorated.__name__ = f.__name__
    return decorated

# Authentication routes
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')
    
    user = db.users.find_one({'user_id': user_id})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': user['user_id'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(days=1)
    }, JWT_SECRET)
    
    return jsonify({'token': token, 'role': user['role']})

# User management routes
@app.route('/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json()
    if db.users.find_one({'user_id': data['user_id']}):
        return jsonify({'error': 'User ID already exists'}), 400
    
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    user = {
        'user_id': data['user_id'],
        'phone': data['phone'],
        'password': hashed_password,
        'role': 'user',
        'delivery_address': data.get('delivery_address', ''),
        'created_at': datetime.utcnow()
    }
    
    db.users.insert_one(user)
    return jsonify({'message': 'User created successfully'})

@app.route('/users/<user_id>', methods=['PUT'])
@auth_required
def update_user(user_id):
    if request.user['role'] != 'admin' and request.user['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    update_data = {}
    
    if 'delivery_address' in data:
        update_data['delivery_address'] = data['delivery_address']
    
    if update_data:
        db.users.update_one({'user_id': user_id}, {'$set': update_data})
    
    return jsonify({'message': 'User updated successfully'})

@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    users = list(db.users.find({'role': 'user'}, {'password': 0}))
    return jsonify({'users': users})

# Tiffin management routes
@app.route('/tiffins', methods=['POST'])
@admin_required
def create_tiffin():
    data = request.get_json()
    tiffin = {
        'name': data['name'],
        'description': data['description'],
        'price': data['price'],
        'date': datetime.strptime(data['date'], '%Y-%m-%d'),
        'time_slot': data['time_slot'],
        'cancellation_time': datetime.strptime(data['cancellation_time'], '%Y-%m-%d %H:%M'),
        'max_capacity': data.get('max_capacity'),
        'assigned_users': [],
        'status': 'preparing',
        'created_at': datetime.utcnow()
    }
    
    db.tiffins.insert_one(tiffin)
    return jsonify({'message': 'Tiffin created successfully'})

@app.route('/tiffins/<tiffin_id>/status', methods=['PUT'])
@admin_required
def update_tiffin_status(tiffin_id):
    data = request.get_json()
    db.tiffins.update_one(
        {'_id': ObjectId(tiffin_id)},
        {'$set': {'status': data['status']}}
    )
    return jsonify({'message': 'Tiffin status updated'})

@app.route('/tiffins/upcoming', methods=['GET'])
@auth_required
def get_upcoming_tiffins():
    tiffins = list(db.tiffins.find({
        'date': {'$gte': datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)}
    }).sort('date', 1))
    return jsonify({'tiffins': tiffins})

@app.route('/tiffins/<tiffin_id>/cancel', methods=['POST'])
@auth_required
def cancel_tiffin(tiffin_id):
    tiffin = db.tiffins.find_one({'_id': ObjectId(tiffin_id)})
    if not tiffin:
        return jsonify({'error': 'Tiffin not found'}), 404
    
    if datetime.utcnow() > tiffin['cancellation_time']:
        return jsonify({'error': 'Cancellation time has passed'}), 400
    
    db.tiffins.update_one(
        {'_id': ObjectId(tiffin_id)},
        {'$pull': {'assigned_users': request.user['user_id']}}
    )
    
    return jsonify({'message': 'Tiffin cancelled successfully'})

# History routes
@app.route('/history', methods=['GET'])
@auth_required
def get_history():
    user_id = request.user['user_id']
    history = list(db.tiffins.find({
        'assigned_users': user_id,
        'date': {'$lt': datetime.utcnow()}
    }).sort('date', -1))
    return jsonify({'history': history})

# Invoice routes
@app.route('/invoices', methods=['GET'])
@auth_required
def get_invoices():
    user_id = request.user['user_id']
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = {'assigned_users': user_id}
    if start_date and end_date:
        query['date'] = {
            '$gte': datetime.strptime(start_date, '%Y-%m-%d'),
            '$lte': datetime.strptime(end_date, '%Y-%m-%d')
        }
    
    tiffins = list(db.tiffins.find(query))
    total_amount = sum(tiffin['price'] for tiffin in tiffins)
    
    return jsonify({
        'tiffins': tiffins,
        'total_amount': total_amount
    })

# Notice routes
@app.route('/notices', methods=['POST'])
@admin_required
def create_notice():
    data = request.get_json()
    notice = {
        'title': data['title'],
        'content': data['content'],
        'created_at': datetime.utcnow()
    }
    db.notices.insert_one(notice)
    return jsonify({'message': 'Notice created successfully'})

@app.route('/notices', methods=['GET'])
@auth_required
def get_notices():
    notices = list(db.notices.find().sort('created_at', -1))
    return jsonify({'notices': notices})

# Poll routes
@app.route('/polls', methods=['POST'])
@admin_required
def create_poll():
    data = request.get_json()
    poll = {
        'question': data['question'],
        'options': data['options'],
        'start_date': datetime.strptime(data['start_date'], '%Y-%m-%d'),
        'end_date': datetime.strptime(data['end_date'], '%Y-%m-%d'),
        'votes': {option: [] for option in data['options']},
        'created_at': datetime.utcnow()
    }
    db.polls.insert_one(poll)
    return jsonify({'message': 'Poll created successfully'})

@app.route('/polls/<poll_id>/vote', methods=['POST'])
@auth_required
def vote_poll(poll_id):
    data = request.get_json()
    poll = db.polls.find_one({'_id': ObjectId(poll_id)})
    
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404
    
    if datetime.utcnow() > poll['end_date']:
        return jsonify({'error': 'Poll has ended'}), 400
    
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

@app.route('/polls/active', methods=['GET'])
@auth_required
def get_active_polls():
    polls = list(db.polls.find({
        'end_date': {'$gte': datetime.utcnow()}
    }).sort('end_date', 1))
    return jsonify({'polls': polls})

# Special requests routes
@app.route('/requests', methods=['POST'])
@auth_required
def create_request():
    data = request.get_json()
    special_request = {
        'user_id': request.user['user_id'],
        'description': data['description'],
        'date': datetime.strptime(data['date'], '%Y-%m-%d'),
        'status': 'pending',
        'created_at': datetime.utcnow()
    }
    db.special_requests.insert_one(special_request)
    return jsonify({'message': 'Request created successfully'})

@app.route('/requests', methods=['GET'])
@admin_required
def get_requests():
    requests = list(db.special_requests.find().sort('created_at', -1))
    return jsonify({'requests': requests})

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

# Keep-alive scheduler
def ping_server():
    try:
        requests.get('https://your-render-url.onrender.com/health')
    except:
        pass

scheduler = BackgroundScheduler()
scheduler.add_job(ping_server, 'interval', minutes=10)
scheduler.start()

if __name__ == '__main__':
    app.run(debug=True)
