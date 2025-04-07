from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import pandas as pd
import stripe
import os
import logging
import certifi
from dotenv import load_dotenv
import jwt
from firebase_admin import auth, credentials
import firebase_admin
from functools import wraps
from datetime import datetime
import bcrypt
from werkzeug.utils import secure_filename
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

# Load environment variables
load_dotenv(dotenv_path="secret.env")

# Configure Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', '').strip()
if not stripe.api_key:
    logging.warning("⚠️ Stripe key not found, proceeding without Stripe")

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")

# Update CORS settings
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:5001", "http://127.0.0.1:5001"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Accept"],
        "expose_headers": ["Set-Cookie"],
        "supports_credentials": True
    }
})

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Connect to MongoDB
MONGO_CONNECTION_STRING = "mongodb+srv://km0848230:5C4s8HSfEjfphlX5@cluster0.6rbbd.mongodb.net/mydatabase?retryWrites=true&w=majority"
client = MongoClient(MONGO_CONNECTION_STRING, tlsCAFile=certifi.where())
db = client["mydatabase"]
products_collection = db["products"]
orders_collection = db["orders"]
users_collection = db["users"]
cart_collection = db["carts"]
complaints_collection = db["complaints"]
logger.info("✅ Successfully connected to MongoDB!")

# Update 'kareem' to admin role (run once)
users_collection.update_one({"username": "kareem"}, {"$set": {"role": "admin"}}, upsert=True)
logger.info("✅ Updated user 'kareem' to have role 'admin' in the database")

# Define constants
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
UPLOAD_FOLDER = 'static/img/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Twilio configuration for WhatsApp
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN else None

# Function to send WhatsApp message
def send_whatsapp_message(to_number, message):
    if not twilio_client:
        logger.error("❌ Twilio client not initialized. Check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.")
        return False
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=f"whatsapp:{to_number}"
        )
        logger.info(f"✅ WhatsApp message sent to {to_number}")
        return True
    except TwilioRestException as e:
        logger.error(f"❌ Failed to send WhatsApp message: {e}")
        return False

# # Initialize Firebase
# cred = credentials.Certificate("C:/Users/HP/Desktop/Build-Ecommerce-Website-With-HTML-CSS-JavaScript-main/web-site-of-market-firebase-adminsdk-fbsvc-7197b01469.json")
# firebase_admin.initialize_app(cred)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        logger.info(f"Token received in request: {token}")
        if not token:
            logger.error("No token provided in request cookies")
            return jsonify({"error": "❌ Token missing, please log in"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            logger.info(f"Decoded token data: {data}")
            request.user = data
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({"error": "❌ Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# Login API
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify({"status": "ok"})
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    try:
        data = request.get_json()
        logger.info(f"Login attempt with data: {data}")
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'success': False, 'message': '❌ Please enter username and password'}), 400

        username = data.get('username')
        password = data.get('password')

        user = users_collection.find_one({'username': username})
        if not user:
            logger.warning(f"User not found: {username}")
            return jsonify({'success': False, 'message': '❌ Invalid login credentials'}), 401

        stored_password = user['password']
        if isinstance(stored_password, str) and not stored_password.startswith('$2b$'):
            if stored_password == password:
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
                users_collection.update_one(
                    {'_id': user['_id']},
                    {'$set': {'password': hashed_password.decode('utf-8')}}
                )
                logger.info(f"Updated plain-text password for {username} to hashed format")
            else:
                return jsonify({'success': False, 'message': '❌ Invalid login credentials'}), 401
        else:
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                logger.warning(f"Password mismatch for user: {username}")
                return jsonify({'success': False, 'message': '❌ Invalid login credentials'}), 401

        role = user.get('role') or ('admin' if username in ['admin', 'kareem'] else 'user')
        token = jwt.encode({'username': username, 'role': role}, SECRET_KEY, algorithm='HS256')
        logger.info(f"Generated token for {username} with role {role}: {token}")
        response = jsonify({
            'success': True,
            'role': role,
            'username': username,
            'message': '✅ Login successful'
        })
        response.set_cookie('token', token, httponly=True, secure=False, samesite='Lax', path='/')
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://127.0.0.1:5001')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        logger.info(f"Login successful for {username}, cookie set with token: {token}")
        return response

    except Exception as e:
        logger.error(f"Login failed for user {username}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': '❌ Login failed',
            'error': str(e)
        }), 500

# Register API
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'email' not in data or 'password' not in data:
            return jsonify({'success': False, 'message': '❌ Please enter all required fields'}), 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if len(password) < 6:
            return jsonify({'success': False, 'message': '❌ Password must be at least 6 characters'}), 400

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        if users_collection.find_one({'username': username}):
            return jsonify({'success': False, 'message': '❌ Username already exists'}), 400
        
        if users_collection.find_one({'email': email}):
            return jsonify({'success': False, 'message': '❌ Email already exists'}), 400

        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password.decode('utf-8'),
            'role': 'user',
            'created_at': datetime.utcnow()
        }

        users_collection.insert_one(user_data)
        logger.info(f"New user registered: {username}")
        
        return jsonify({
            'success': True,
            'message': '✅ Account created successfully',
            'user': {'username': username, 'email': email}
        })

    except Exception as e:
        logger.error(f"Registration failed: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': '❌ Failed to create account',
            'error': str(e)
        }), 500

# Google Login API
@app.route('/api/google-login', methods=['POST'])
def google_login():
    try:
        data = request.get_json()
        token = data.get('token')

        decoded_token = auth.verify_id_token(token)
        email = decoded_token['email']
        uid = decoded_token['uid']

        user = users_collection.find_one({'uid': uid})
        if not user:
            users_collection.insert_one({'uid': uid, 'email': email, 'role': 'user', 'created_at': datetime.utcnow()})
            role = 'user'
        else:
            role = user.get('role', 'user')

        if email == 'admin@example.com':
            role = 'admin'

        token = jwt.encode({'email': email, 'role': role}, SECRET_KEY, algorithm='HS256')
        response = jsonify({'success': True, 'role': role})
        response.set_cookie('token', token, httponly=True, secure=False, samesite='Lax', domain='localhost', path='/')
        logger.info(f"✅ Google login successful for {email}")
        return response
    except Exception as e:
        logger.error(f"❌ Google login failed: {e}")
        return jsonify({'success': False, 'message': str(e)}), 401

# Reset Passwords API
@app.route('/api/reset_passwords', methods=['POST'])
@token_required
def reset_passwords():
    if request.user.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        users = users_collection.find({})
        updated_count = 0
        
        for user in users:
            password = user.get('password')
            if isinstance(password, str) and not password.startswith('$2b$'):
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
                users_collection.update_one(
                    {'_id': user['_id']},
                    {'$set': {'password': hashed.decode('utf-8'), 'password_reset_required': False}}
                )
                updated_count += 1
            
        return jsonify({
            "message": f"Updated {updated_count} passwords to hashed format",
            "updated_count": updated_count
        })
        
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Check authentication status
@app.route('/api/check_auth', methods=['GET', 'OPTIONS'])
def check_auth():
    if request.method == 'OPTIONS':
        response = jsonify({"status": "ok"})
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    try:
        token = request.cookies.get('token')
        logger.info(f"Checking auth with token: {token}")
        if not token:
            logger.error("No token found in check_auth request")
            response = jsonify({'authenticated': False, 'message': 'No token provided'})
            response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://127.0.0.1:5001')
            return response, 401
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        logger.info(f"Token decoded successfully: {data}")
        response = jsonify({'authenticated': True, 'role': data.get('role', 'user'), 'username': data.get('username')})
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://127.0.0.1:5001')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token in check_auth: {e}")
        response = jsonify({'authenticated': False, 'message': 'Invalid token'})
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://127.0.0.1:5001')
        return response, 401
    except Exception as e:
        logger.error(f"❌ Authentication check failed: {e}")
        response = jsonify({'authenticated': False, 'message': 'Authentication check failed'})
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://127.0.0.1:5001')
        return response, 500

# Logout API
@app.route('/api/logout', methods=['POST', 'OPTIONS'])
def logout():
    if request.method == 'OPTIONS':
        response = jsonify({"status": "ok"})
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    response = jsonify({'success': True, 'message': '✅ Logged out successfully'})
    response.set_cookie('token', '', expires=0, httponly=True, secure=False, samesite='Lax', path='/')
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://127.0.0.1:5001')
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    logger.info("User logged out, token cookie cleared")
    return response

# Get all users
# Get all users
@app.route('/api/users', methods=['GET'])
@token_required
def get_users():
    try:
        if request.user.get('role') != 'admin':
            return jsonify({"error": "❌ Must be an admin to access this data"}), 403

        # جلب جميع المستخدمين المسجلين
        users = list(users_collection.find({}, {'_id': 0, 'password': 0}))
        user_emails = {user.get("email", "") for user in users}

        # جلب جميع الطلبات لتحديد العملاء غير المسجلين (الضيوف)
        orders = list(orders_collection.find({}))
        guest_users = set()
        for order in orders:
            email = order.get("customerDetails", {}).get("email", "Not specified")
            if email != "Not specified" and email not in user_emails:
                guest_users.add(email)

        # إضافة العملاء غير المسجلين إلى القائمة
        for guest_email in guest_users:
            orders_for_guest = [o for o in orders if o.get("customerDetails", {}).get("email") == guest_email]
            order_count = len(orders_for_guest)
            total_items_ordered = sum(sum(item["quantity"] for item in order.get("items", [])) for order in orders_for_guest)
            products_ordered = {}
            for order in orders_for_guest:
                for item in order.get("items", []):
                    product_id = item["id"]
                    products_ordered[product_id] = products_ordered.get(product_id, 0) + item["quantity"]

            users.append({
                "username": "Guest",
                "email": guest_email,
                "orderCount": order_count,
                "totalItemsOrdered": total_items_ordered,
                "productsOrdered": [
                    {
                        "productId": pid,
                        "quantity": qty,
                        "name": (product["name"] if (product := products_collection.find_one({"id": pid}, {"name": 1})) else "غير معروف")
                    }
                    for pid, qty in products_ordered.items()
                ],
                "role": "guest"
            })

        # معالجة بيانات المستخدمين المسجلين
        for user in users:
            if user.get("role") != "guest":  # لا نعيد معالجة الضيوف
                email = user.get("email", "")
                username = user.get("username", "")
                orders = list(orders_collection.find({"customerDetails.email": email}))
                order_count = len(orders)
                total_items_ordered = sum(sum(item["quantity"] for item in order.get("items", [])) for order in orders)
                products_ordered = {}
                for order in orders:
                    for item in order.get("items", []):
                        product_id = item["id"]
                        products_ordered[product_id] = products_ordered.get(product_id, 0) + item["quantity"]
                
                user['orderCount'] = order_count
                user['totalItemsOrdered'] = total_items_ordered
                user['productsOrdered'] = [
                    {
                        "productId": pid,
                        "quantity": qty,
                        "name": (product["name"] if (product := products_collection.find_one({"id": pid}, {"name": 1})) else "غير معروف")
                    }
                    for pid, qty in products_ordered.items()
                ]

        logger.info(f"✅ Retrieved {len(users)} users successfully (including guests)")
        return jsonify(users), 200
    except Exception as e:
        logger.error(f"❌ Failed to retrieve users: {e}")
        return jsonify({'error': '❌ Failed to retrieve users'}), 500


# Upload image API
@app.route("/api/upload_image", methods=["POST"])
@token_required
def upload_image():
    try:
        if "file" not in request.files:
            return jsonify({"error": "❌ No file provided"}), 400
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "❌ No file selected"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "❌ Unsupported file type"}), 400

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)
        image_url = f"/static/img/uploads/{file.filename}"
        logger.info(f"✅ Image uploaded: {image_url}")
        return jsonify({"imagePath": image_url})
    except Exception as e:
        logger.error(f"❌ Image upload failed: {e}")
        return jsonify({"error": "❌ Image upload failed"}), 500

# Helper function for allowed file types
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Export products to Excel
def export_products_to_excel():
    try:
        products_list = list(products_collection.find({}, {"_id": 0}))
        if not products_list:
            logger.warning("❌ No products to export")
            return None
        df = pd.DataFrame(products_list)
        file_path = "products.xlsx"
        df.to_excel(file_path, index=False)
        logger.info(f"✅ Products exported to {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"❌ Failed to export products: {e}")
        return None

# HTML Routes
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/shop')
def shop():
    return render_template("shop.html")

@app.route('/shoes')
def shoes_page():
    return render_template("shoes.html")

@app.route('/clothes')
def clothes_page():
    return render_template("clothes.html")

@app.route('/watches')
def watches_page():
    return render_template("watches.html")

@app.route('/login')
@app.route('/login.html')
def login_page():
    return render_template("login.html")

@app.route('/register')
def register_page():
    return render_template('register.html')

# Admin pages
@app.route('/analysis.html')
@token_required
def analysis_page():
    if request.user.get('role') != 'admin':
        logger.error(f"Access denied for user {request.user.get('username')}: Not an admin")
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("analysis.html")

@app.route('/add-product.html')
@token_required
def add_product_page():
    if request.user['role'] != 'admin':
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("add-product.html")

@app.route('/delete-product.html')
@token_required
def delete_product_page():
    if request.user['role'] != 'admin':
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("delete-product.html")

@app.route('/edit-product.html')
@token_required
def edit_product_page():
    if request.user.get('role') != 'admin':
        logger.error(f"Access denied for user {request.user.get('username')}: Not an admin")
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("edit-product.html")
@app.route('/dashboard.html')
@token_required
def dashboard_page():
    if request.user.get('role') != 'admin':
        logger.error(f"Access denied for user {request.user.get('username')}: Not an admin")
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("dashboard.html")
@app.route('/product_analysis.html')
@token_required
def product_analysis_page():
    if request.user.get('role') != 'admin':
        logger.error(f"Access denied for user {request.user.get('username')}: Not an admin")
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("product_analysis.html")
@app.route('/orders.html')
@token_required
def orders_page():
    if request.user['role'] != 'admin':
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("orders.html")

@app.route('/order-details.html')
@token_required
def order_details_page():
    if request.user['role'] != 'admin':
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("order-details.html")

@app.route('/users.html')
@token_required
def users_page():
    if request.user['role'] != 'admin':
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("users.html")

@app.route('/admin')
@token_required
def admin_page():
    if request.user['role'] != 'admin':
        return jsonify({"error": "❌ Access denied to admin page"}), 403
    return render_template("analysis.html")

@app.route('/product/<product_id>')
def product_page(product_id):
    return render_template('product.html')
@app.route('/api/product_analysis/<product_id>', methods=['GET'])
@token_required
def product_analysis(product_id):
    try:
        if request.user.get('role') != 'admin':
            return jsonify({"error": "❌ Not allowed to view product analysis"}), 403
        
        product = products_collection.find_one({"id": product_id})
        if not product:
            return jsonify({"error": "❌ المنتج غير موجود"}), 404
        
        product["_id"] = str(product["_id"])
        sales_data = orders_collection.aggregate([
            {"$unwind": "$items"},
            {"$match": {"items.id": product_id}},
            {"$group": {"_id": "$items.id", "total_sold": {"$sum": "$items.quantity"}}}
        ])
        product["total_sold"] = next(sales_data, {}).get("total_sold", 0)
        
        return jsonify(product), 200
    except Exception as e:
        logger.error(f"❌ فشل في تحليل المنتج: {e}")
        return jsonify({"error": "❌ فشل في تحليل المنتج"}), 500
# Get single product API
@app.route('/api/products/<product_id>', methods=['GET'])
@token_required
def get_product(product_id):
    try:
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if product:
            product['_id'] = str(product['_id'])
            return jsonify(product), 200
        return jsonify({"error": "❌ المنتج غير موجود"}), 404
    except Exception as e:
        logger.error(f"❌ خطأ في جلب المنتج: {e}")
        return jsonify({"error": "❌ فشل في جلب المنتج"}), 500

# Get products API
@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        category = request.args.get("category")
        product_id = request.args.get("id")
        if product_id:
            product = products_collection.find_one({"id": product_id})
            if product:
                product["_id"] = str(product["_id"])
                # إضافة عدد المبيعات
                sales_count = orders_collection.aggregate([
                    {"$unwind": "$items"},
                    {"$match": {"items.id": product_id}},
                    {"$group": {"_id": "$items.id", "total_sold": {"$sum": "$items.quantity"}}}
                ])
                product["total_sold"] = next(sales_count, {}).get("total_sold", 0)
                return jsonify(product), 200
            return jsonify({"error": "❌ المنتج غير موجود"}), 404
        
        query = {"category": category} if category else {}
        products_list = list(products_collection.find(query))
        for product in products_list:
            product["_id"] = str(product["_id"])
            # إضافة عدد المبيعات لكل منتج
            sales_count = orders_collection.aggregate([
                {"$unwind": "$items"},
                {"$match": {"items.id": product["id"]}},
                {"$group": {"_id": "$items.id", "total_sold": {"$sum": "$items.quantity"}}}
            ])
            product["total_sold"] = next(sales_count, {}).get("total_sold", 0)
        return jsonify(products_list if products_list else {"message": "❌ لا توجد منتجات متاحة"}), 200
    except Exception as e:
        logger.error(f"❌ فشل في جلب المنتجات: {e}")
        return jsonify({"error": "❌ فشل في جلب المنتجات"}), 500
    
@app.route('/api/add_product', methods=['POST'])
@token_required
def add_product():
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ غير مسموح لك بإضافة منتج"}), 403

        product_data = {
            "name": request.form.get("name"),
            "price": float(request.form.get("price", 0)),
            "discount": float(request.form.get("discount", 0)),
            "amount": int(request.form.get("amount", 1)),
            "description": request.form.get("description"),
            "category": request.form.get("category"),
            "created_at": datetime.utcnow(),
            "id": str(ObjectId()),
            "images": []
        }

        # Handle main image upload to Cloudinary
        if 'mainImage' in request.files:
            main_image = request.files['mainImage']
            if main_image and allowed_file(main_image.filename):
                upload_result = cloudinary.uploader.upload(main_image, folder="products")
                product_data["image"] = upload_result["secure_url"]
                product_data["images"].append(upload_result["secure_url"])
            else:
                return jsonify({"error": "❌ Invalid main image file"}), 400

        # Handle additional images upload to Cloudinary
        additional_images = request.files.getlist('additionalImages')
        for img in additional_images:
            if img and allowed_file(img.filename):
                upload_result = cloudinary.uploader.upload(img, folder="products")
                product_data["images"].append(upload_result["secure_url"])

        products_collection.insert_one(product_data)
        return jsonify({
            "success": True,
            "message": "✅ تم إضافة المنتج بنجاح",
            "id": product_data["id"],
            "productUrl": f"/product/{product_data['id']}"
        }), 200

    except Exception as e:
        logger.error(f"❌ فشل في إضافة المنتج: {str(e)}")
        return jsonify({"error": f"❌ فشل في إضافة المنتج: {str(e)}"}), 500
# Delete product API
@app.route('/api/delete_product', methods=['DELETE'])
@token_required
def delete_product():
    try:
        product_id = request.args.get('id')
        result = products_collection.delete_one({"_id": ObjectId(product_id)})
        if result.deleted_count > 0:
            return jsonify({"message": "✅ تم حذف المنتج بنجاح"}), 200
        return jsonify({"error": "❌ المنتج غير موجود"}), 404
    except Exception as e:
        logger.error(f"❌ فشل في حذف المنتج: {e}")
        return jsonify({"error": "❌ فشل في حذف المنتج"}), 500

# Delete all products API
@app.route('/api/delete_all_products', methods=['DELETE'])
@token_required
def delete_all_products():
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to delete all products"}), 403
        result = products_collection.delete_many({})
        return jsonify({"message": f"✅ تم حذف {result.deleted_count} منتجات بنجاح"}), 200
    except Exception as e:
        logger.error(f"❌ فشل في حذف جميع المنتجات: {e}")
        return jsonify({"error": "❌ فشل في حذف جميع المنتجات"}), 500
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # أضف الامتدادات المسموحة

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/products/<product_id>', methods=['PUT'])
def update_product(product_id):
    try:
        update_data = {}
        existing_product = products_collection.find_one({'id': product_id})

        if not existing_product:
            return jsonify({"success": False, "message": "❌ Product not found"}), 404

        # Handle deletion of a specific image
        if 'delete_image_url' in request.form:
            image_to_delete = request.form['delete_image_url']
            if image_to_delete:
                update_data['images'] = [img for img in existing_product.get('images', []) if img != image_to_delete]
                if existing_product.get('image') == image_to_delete:
                    update_data['image'] = update_data['images'][0] if update_data['images'] else None

        # Handle deletion of all images
        if 'delete_all_images' in request.form and request.form['delete_all_images'] == 'true':
            update_data['images'] = []
            update_data['image'] = None

        # Handle new main image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                update_data['image'] = f"/static/img/uploads/{filename}"
            else:
                return jsonify({"success": False, "message": "❌ Invalid image file"}), 400

        # Handle additional images upload
        if 'images' in request.files:
            files = request.files.getlist('images')
            new_images = existing_product.get('images', [])
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)
                    new_images.append(f"/static/img/uploads/{filename}")
                else:
                    return jsonify({"success": False, "message": "❌ Invalid additional image file"}), 400
            update_data['images'] = new_images

        # Ensure main image is in images array
        if 'image' in update_data and update_data['image']:
            if 'images' not in update_data:
                update_data['images'] = existing_product.get('images', [])
            if update_data['image'] not in update_data['images']:
                update_data['images'].insert(0, update_data['image'])

        # Handle form fields
        if request.form:
            if 'name' in request.form and request.form['name'].strip():
                update_data['name'] = request.form['name']
            if 'price' in request.form:
                try:
                    update_data['price'] = float(request.form['price'])
                except ValueError:
                    return jsonify({"success": False, "message": "❌ Invalid price value"}), 400
            if 'discount' in request.form:
                try:
                    update_data['discount'] = float(request.form['discount'])
                except ValueError:
                    return jsonify({"success": False, "message": "❌ Invalid discount value"}), 400
            if 'amount' in request.form:
                try:
                    update_data['amount'] = int(request.form['amount'])
                except ValueError:
                    return jsonify({"success": False, "message": "❌ Invalid amount value"}), 400
            if 'description' in request.form:
                update_data['description'] = request.form['description']
            if 'ratings' in request.form:
                try:
                    update_data['ratings'] = json.loads(request.form['ratings'])
                    update_data['average_rating'] = sum(r['rating'] for r in update_data['ratings']) / len(update_data['ratings']) if update_data['ratings'] else 0
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    return jsonify({"success": False, "message": f"❌ Invalid ratings data: {str(e)}"}), 400

        # Allow update even if no new data is provided (e.g., for deletions)
        result = products_collection.update_one(
            {'id': product_id},
            {'$set': update_data}
        )

        if result.modified_count > 0 or not update_data:
            return jsonify({"success": True, "message": "✅ Product updated successfully"})
        else:
            return jsonify({"success": False, "message": "❌ No changes detected or product already up-to-date"}), 200

    except Exception as e:
        logger.error(f"Error updating product: {str(e)}")
        return jsonify({"success": False, "message": f"❌ Server error: {str(e)}"}), 500
# دالة لإرسال رسالة WhatsApp (افتراضية)
def send_whatsapp_message(phone_number, message):
    logger.info(f"Sending WhatsApp message to {phone_number}: {message}")
    # أضف هنا الكود الفعلي لإرسال الرسالة عبر API WhatsApp

def send_whatsapp_message(phone_number, message):
    logger.info(f"محاكاة إرسال رسالة WhatsApp إلى {phone_number}: {message}")
    # هنا يمكنك إضافة كود فعلي لـ WhatsApp API مثل Twilio

@app.route('/api/place_order', methods=['POST'])
def place_order():
    try:
        order_data = request.get_json()
        logger.info(f"Received order data: {order_data}")
        if not order_data:
            return jsonify({"error": "❌ Invalid order data"}), 400

        # التحقق من البيانات الإلزامية للدفع عند الاستلام
        if order_data.get("paymentMethod") == "delivery":
            required_fields = ["name", "phone", "altPhone", "address"]
            if not all(key in order_data and order_data[key] for key in required_fields):
                return jsonify({"error": "❌ Missing required fields (name, phone, altPhone, address)"}), 400

        # تفاصيل العميل
        customer_details = {
            "name": order_data.get("name", "Not specified"),
            "phone": order_data.get("phone", ""),
            "altPhone": order_data.get("altPhone", ""),
            "email": order_data.get("email", "Not specified"),
            "address": order_data.get("address", "Not specified")
        }

        items = order_data.get("items", [])
        if not items:
            return jsonify({"error": "❌ Cart is empty"}), 400

        total = 0
        validated_items = []

        # التحقق من المنتجات وحساب الإجمالي
        for item in items:
            product = products_collection.find_one({"id": item.get("id")})
            if product:
                price = float(product.get("price", 0))
                discount = float(product.get("discount", 0)) if product.get("discount") else 0
                final_price = price - (price * discount / 100) if discount else price
                quantity = int(item.get("quantity", 1))
                total += final_price * quantity
                validated_items.append({
                    "id": item["id"],
                    "name": product.get("name"),
                    "price": final_price,
                    "quantity": quantity,
                    "image": product.get("image", "/static/img/default-product.jpg")
                })
            else:
                logger.warning(f"❌ Product {item.get('id')} not found in database")

        if not validated_items:
            return jsonify({"error": "❌ No valid products in order"}), 400

        # التحقق من الكمية وتحديث المخزون
        for item in validated_items:
            product = products_collection.find_one({"id": item["id"]})
            if product:
                current_amount = int(product.get("amount", 0))
                new_amount = current_amount - item["quantity"]
                if new_amount < 0:
                    return jsonify({"error": f"❌ Insufficient quantity for product {item['id']}"}), 400
                products_collection.update_one(
                    {"id": item["id"]},
                    {"$set": {"amount": new_amount}}
                )

        # تنسيق الطلب
        normalized_order = {
            "customerDetails": customer_details,
            "items": validated_items,
            "paymentMethod": order_data.get("paymentMethod", "Not specified"),
            "status": "pending",
            "total": round(total, 2),
            "created_at": datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        }

        # إضافة الطلب إلى قاعدة البيانات
        result = orders_collection.insert_one(normalized_order)
        order_id = str(result.inserted_id)
        cart_collection.delete_one({"user": customer_details["email"]})
        logger.info(f"✅ New order placed: {order_id}")

        # إعداد رسالة WhatsApp المحدثة
        whatsapp_message = ""
        if order_data.get("paymentMethod") == "delivery":
            whatsapp_message = (
                f"طلب جديد (الدفع عند الاستلام):\n"
                f"الاسم: {customer_details['name']}\n"
                f"رقم الهاتف الأساسي: {customer_details['phone']}\n"
                f"رقم الهاتف الثاني: {customer_details['altPhone']}\n"
                f"البريد الإلكتروني: {customer_details['email'] if customer_details['email'] != 'Not specified' else 'غير محدد'}\n"
                f"العنوان: {customer_details['address']}\n"
                f"الإجمالي: {round(total, 2)}"
            )
        else:
            whatsapp_message = (
                f"طلب جديد (فيزا):\n"
                f"اسم صاحب البطاقة: {order_data.get('cardDetails', {}).get('cardName', 'غير محدد')}\n"
                f"رقم البطاقة: {order_data.get('cardDetails', {}).get('cardNumber', 'غير محدد')[-4:].rjust(len(order_data.get('cardDetails', {}).get('cardNumber', '')), '*')}\n"
                f"الإجمالي: {round(total, 2)}"
            )

        # إرسال رسالة WhatsApp
        send_whatsapp_message("+201022957599", whatsapp_message)

        return jsonify({
            "message": "✅ Order placed successfully!",
            "order_id": order_id,
            "redirect_url": f"/order_confirmation/{order_id}"
        })
    except Exception as e:
        logger.error(f"❌ Failed to place order: {e}")
        return jsonify({"error": f"❌ Failed to place order: {str(e)}"}), 500

@app.route('/order_confirmation/<order_id>')
def order_confirmation(order_id):
    try:
        if not ObjectId.is_valid(order_id):
            return render_template("order_confirmation.html", order=None, error="رقم الطلب غير صالح")
            
        order = orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return render_template("order_confirmation.html", order=None, error="لم يتم العثور على الطلب")
        
        order_items = order.get("items", [])
        if not isinstance(order_items, (list, tuple)):
            order_items = []
        
        for item in order_items:
            product = products_collection.find_one({"id": item["id"]})
            item["image"] = product.get("image", "/static/img/default-product.jpg") if product else "/static/img/default-product.jpg"
        
        order_date = order.get("date", datetime.utcnow())
        if isinstance(order_date, str):
            order_date = datetime.fromisoformat(order_date)
        
        return render_template(
            "order_confirmation.html",
            order=order,
            order_items=order_items,
            order_date=order_date.strftime("%Y-%m-%d %H:%M"),
            payment_method=order.get("paymentMethod", "غير محدد")
        )
    except Exception as e:
        logger.error(f"خطأ في عرض تأكيد الطلب: {str(e)}")
        return render_template("order_confirmation.html", order=None, error="حدث خطأ أثناء معالجة الطلب")
# Cart route
@app.route('/cart')
def cart():
    return render_template('cart.html')

# Checkout route
@app.route('/checkout')
def checkout():
    return render_template('checkout.html')

# Store cart API
@app.route('/api/store_cart', methods=['POST'])
def store_cart():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "❌ Invalid cart data"}), 400

        token = request.cookies.get('token')
        user_email = "guest"
        if token:
            try:
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                user_email = decoded.get("email", decoded.get("username", "guest"))
            except jwt.InvalidTokenError:
                pass

        validated_cart = []
        for item in data:
            product = products_collection.find_one({"id": item.get("id")})
            if product:
                validated_cart.append({
                    "id": item["id"],
                    "quantity": int(item.get("quantity", 1))
                })
            else:
                logger.warning(f"❌ Product {item.get('id')} not found")

        if not validated_cart:
            return jsonify({"error": "❌ No valid products in cart"}), 400

        cart_collection.update_one(
            {"user": user_email},
            {"$set": {"items": validated_cart, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        logger.info(f"✅ Cart stored for {user_email}: {validated_cart}")
        return jsonify({"message": "✅ Item added to cart successfully!"}), 200
    except Exception as e:
        logger.error(f"❌ Failed to store cart: {e}")
        return jsonify({"error": str(e)}), 400

# Get all orders
@app.route('/api/orders', methods=['GET'])
@token_required
def get_orders():
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to view orders"}), 403

        orders = list(orders_collection.find({}))
        for order in orders:
            order["_id"] = str(order["_id"])
            customer = order.get("customerDetails", {})
            customer["name"] = customer.get("name", "Not specified")
            customer["email"] = customer.get("email", "Not specified")
            customer["address"] = customer.get("address", "Not specified")
            customer["phone"] = customer.get("phone", "")
            order["customerDetails"] = customer
            if "cart" in order:
                order["items"] = order.pop("cart")
        logger.info(f"✅ Retrieved {len(orders)} orders successfully")
        return jsonify(orders), 200
    except Exception as e:
        logger.error(f"❌ Failed to retrieve orders: {e}")
        return jsonify({"error": "❌ Failed to retrieve orders."}), 500

# Get single order
@app.route('/api/orders/<order_id>', methods=['GET'])
@token_required
def get_order(order_id):
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to view order"}), 403

        order = orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return jsonify({"error": "❌ Order not found"}), 404

        order["_id"] = str(order["_id"])
        customer = order.get("customerDetails", {})
        customer["name"] = customer.get("name", "Not specified")
        customer["email"] = customer.get("email", "Not specified")
        customer["address"] = customer.get("address", "Not specified")
        customer["phone"] = customer.get("phone", "")
        order["customerDetails"] = customer
        if "cart" in order:
            order["items"] = order.pop("cart")
        return jsonify(order), 200
    except ValueError as ve:
        logger.error(f"❌ Invalid order ID: {order_id} - {ve}")
        return jsonify({"error": "❌ Invalid order ID"}), 400
    except Exception as e:
        logger.error(f"❌ Failed to retrieve order: {e}")
        return jsonify({"error": "❌ Failed to retrieve order."}), 500

# Update order status
@app.route('/api/orders/<order_id>', methods=['PUT'])
@token_required
def update_order_status(order_id):
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to update order"}), 403

        data = request.get_json()
        if not data or "status" not in data:
            return jsonify({"error": "❌ Invalid data"}), 400

        result = orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {"$set": {"status": data["status"], "updated_at": datetime.utcnow()}}
        )

        if result.matched_count == 0:
            return jsonify({"error": "❌ Order not found"}), 404

        return jsonify({"message": "✅ تم تحديث حالة الطلب بنجاح"}), 200
    except ValueError as ve:
        logger.error(f"❌ Invalid order ID: {order_id} - {ve}")
        return jsonify({"error": "❌ Invalid order ID"}), 400
    except Exception as e:
        logger.error(f"❌ Failed to update order status: {e}")
        return jsonify({"error": "❌ Failed to update order status."}), 500

# Delete a single order
@app.route('/api/orders/<order_id>', methods=['DELETE'])
@token_required
def delete_order(order_id):
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to delete order"}), 403
        result = orders_collection.delete_one({"_id": ObjectId(order_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "❌ Order not found"}), 404
        return jsonify({"message": "✅ تم حذف الطلب بنجاح"}), 200
    except Exception as e:
        logger.error(f"❌ Failed to delete order: {e}")
        return jsonify({"error": "❌ Failed to delete order"}), 500

# Delete all orders
@app.route('/api/delete_all_orders', methods=['DELETE'])
@token_required
def delete_all_orders():
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to delete all orders"}), 403

        result = orders_collection.delete_many({})
        return jsonify({"message": f"✅ Deleted {result.deleted_count} orders successfully"}), 200
    except Exception as e:
        logger.error(f"❌ Failed to delete all orders: {e}")
        return jsonify({"error": "❌ Failed to delete all orders."}), 500

# Serve uploaded images
@app.route('/static/img/uploads/<path:filename>')
def uploaded_images(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# Support page
@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")
        logger.info(f"New inquiry from {name} - {email}: {subject} - {message}")
        return render_template("support.html", success=True)
    return render_template("support.html", success=False)

# Get complaints
@app.route('/api/complaints', methods=['GET'])
@token_required
def get_complaints():
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to view complaints"}), 403

        complaints = list(complaints_collection.find({}).sort("created_at", -1))
        for complaint in complaints:
            complaint["_id"] = str(complaint["_id"])
        return jsonify(complaints), 200
    except Exception as e:
        logger.error(f"❌ Failed to retrieve complaints: {e}")
        return jsonify({"error": "❌ Failed to retrieve complaints"}), 500

# Update complaint status
@app.route('/api/complaints/<complaint_id>', methods=['PUT'])
@token_required
def update_complaint(complaint_id):
    try:
        if request.user['role'] != 'admin':
            return jsonify({"error": "❌ Not allowed to update complaints"}), 403

        data = request.get_json()
        complaints_collection.update_one(
            {"_id": ObjectId(complaint_id)},
            {"$set": {"status": data.get("status", "pending")}}
        )
        return jsonify({"message": "✅ Complaint status updated"}), 200
    except Exception as e:
        logger.error(f"❌ Failed to update complaint: {e}")
        return jsonify({"error": "❌ Failed to update complaint"}), 500

# Submit complaint
@app.route('/api/submit_complaint', methods=['POST'])
def submit_complaint():
    try:
        data = request.get_json()
        complaint = {
            "name": data.get('name', 'Anonymous'),
            "email": data.get('email', ''),
            "type": data.get('type', 'Complaint'),
            "message": data.get('message'),
            "status": "pending",
            "created_at": datetime.utcnow()
        }
        
        complaints_collection.insert_one(complaint)
        return jsonify({"message": "✅ Your complaint has been received and will be addressed soon"}), 200
    except Exception as e:
        logger.error(f"❌ Failed to submit complaint: {e}")
        return jsonify({"error": "❌ Failed to submit complaint"}), 500

# Rate product
@app.route('/api/rate_product/<product_id>', methods=['POST'])
@token_required
def rate_product(product_id):
    try:
        data = request.get_json()
        rating = data.get('rating')
        comment = data.get('comment', '')

        if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({'error': 'Rating must be an integer between 1 and 5'}), 400

        username = request.user.get('username', request.user.get('email', 'Anonymous'))
        product = products_collection.find_one({'id': product_id})
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        new_rating = {
            'user': username,
            'rating': rating,
            'comment': comment,
            'date': datetime.utcnow()
        }

        products_collection.update_one(
            {'id': product_id},
            {'$push': {'ratings': new_rating}}
        )

        updated_product = products_collection.find_one({'id': product_id})
        ratings = updated_product.get('ratings', [])
        average_rating = sum(r['rating'] for r in ratings) / len(ratings) if ratings else 0
        products_collection.update_one(
            {'id': product_id},
            {'$set': {'average_rating': round(average_rating, 1)}}
        )

        return jsonify({'message': '✅ Rating added successfully'}), 200
    except Exception as e:
        logger.error(f"❌ Failed to rate product: {e}")
        return jsonify({'error': f'Failed to add rating: {str(e)}'}), 500

# Best selling products
@app.route('/api/best_selling', methods=['GET'])
def best_selling():
    try:
        pipeline = [
            {"$unwind": "$items"},
            {"$group": {"_id": "$items.id", "total_sold": {"$sum": "$items.quantity"}}},
            {"$sort": {"total_sold": -1}},
            {"$limit": 10}
        ]
        best_sellers = list(orders_collection.aggregate(pipeline))
        
        product_ids = [item["_id"] for item in best_sellers]
        products = list(products_collection.find({"id": {"$in": product_ids}}))
        
        for product in products:
            for seller in best_sellers:
                if product["id"] == seller["_id"]:
                    product["total_sold"] = seller["total_sold"]
                    break
        
        products.sort(key=lambda x: x.get("total_sold", 0), reverse=True)
        for product in products:
            product["_id"] = str(product["_id"])
        
        return jsonify(products), 200
    except Exception as e:
        logger.error(f"❌ Failed to retrieve best-selling products: {e}")
        return jsonify({"error": "❌ Failed to retrieve best-selling products"}), 500

# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)