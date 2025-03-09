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
from pymongo import MongoClient
import certifi

import certifi
from pymongo import MongoClient
import certifi
from pymongo import MongoClient



# Load environment variables
load_dotenv(dotenv_path="secret.env")

# Configure Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', '').strip()

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app, resources={r"/api/*": {"origins": "*"}}, methods=["GET", "POST", "DELETE", "PUT"])

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Connect to MongoDB with updated certifi CA certificates
MONGO_CONNECTION_STRING = "mongodb+srv://km0848230:5C4s8HSfEjfphlX5@cluster0.6rbbd.mongodb.net/mydatabase?retryWrites=true&w=majority"
client = MongoClient(MONGO_CONNECTION_STRING, tlsCAFile=certifi.where())






db = client["mydatabase"]
products_collection = db["products"]
orders_collection = db["orders"]
logger.info("✅ تم الاتصال بـ MongoDB بنجاح!")

# Image upload folder
UPLOAD_FOLDER = "static/img/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed file types for image upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Upload image API
@app.route("/api/upload_image", methods=["POST"])
def upload_image():
    try:
        if "file" not in request.files:
            return jsonify({"error": "❌ لا توجد ملفات"}), 400
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "❌ لا يوجد ملف محدد"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "❌ نوع الملف غير مدعوم"}), 400

        # Save image
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)
        image_url = f"/static/img/uploads/{file.filename}"
        logger.info(f"✅ تم تحميل الصورة: {image_url}")
        return jsonify({"imagePath": image_url})
    except Exception as e:
        logger.error(f"❌ فشل تحميل الصورة: {e}")
        return jsonify({"error": "❌ فشل تحميل الصورة"}), 500

# Export products to Excel
def export_products_to_excel():
    try:
        products_list = list(products_collection.find({}, {"_id": 0}))
        if not products_list:
            logger.warning("❌ لا توجد منتجات للتصدير")
            return None
        df = pd.DataFrame(products_list)
        file_path = "products.xlsx"
        df.to_excel(file_path, index=False)
        logger.info(f"✅ تم تصدير المنتجات إلى {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"❌ فشل في تصدير المنتجات: {e}")
        return None

# Routes
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

# Get products API
@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        category = request.args.get("category")
        query = {"category": category} if category else {}
        products_list = list(products_collection.find(query, {"_id": 0}))
        return jsonify(products_list if products_list else {"message": "❌ لم يتم العثور على منتجات."}), 200
    except Exception as e:
        logger.error(f"❌ فشل في جلب المنتجات: {e}")
        return jsonify({"error": "❌ فشل في جلب المنتجات."}), 500

# Add product API
@app.route('/api/add_product', methods=['POST'])
def add_product():
    try:
        product_data = request.json
        if not product_data:
            return jsonify({"error": "❌ بيانات غير صالحة"}), 400
        product_data["id"] = str(ObjectId())
        products_collection.insert_one(product_data)
        export_products_to_excel()
        return jsonify({"message": "✅ تم إضافة المنتج بنجاح", "id": product_data["id"]})
    except Exception as e:
        logger.error(f"❌ فشل في إضافة المنتج: {e}")
        return jsonify({"error": "❌ فشل في إضافة المنتج."}), 500

# Delete product API
@app.route('/api/delete_product', methods=['DELETE'])
def delete_product():
    try:
        product_id = request.args.get("id")
        if not product_id:
            return jsonify({"error": "❌ معرف المنتج مفقود"}), 400

        result = products_collection.delete_one({"id": product_id})
        if result.deleted_count == 0:
            return jsonify({"error": "❌ لم يتم العثور على المنتج"}), 404

        return jsonify({"message": "✅ تم حذف المنتج بنجاح"}), 200
    except Exception as e:
        return jsonify({"error": f"❌ خطأ أثناء حذف المنتج: {str(e)}"}), 500

# Update product API
@app.route('/api/update_product', methods=['POST'])
def update_product():
    try:
        product_data = request.json
        if not product_data or "id" not in product_data:
            return jsonify({"error": "❌ بيانات غير صالحة"}), 400

        product_id = product_data["id"]

        updated_data = {}
        if "name" in product_data:
            updated_data["name"] = product_data["name"]
        if "description" in product_data:
            updated_data["description"] = product_data["description"]
        if "price" in product_data:
            updated_data["price"] = product_data["price"]
        if "available" in product_data:
            updated_data["available"] = product_data["available"]
        if "discount" in product_data:
            updated_data["discount"] = product_data["discount"]
        if "amount" in product_data:
            updated_data["amount"] = product_data["amount"]
        if "category" in product_data:
            updated_data["category"] = product_data["category"]

        # Apply discount to price if available
        if "price" in updated_data and "discount" in updated_data:
            price = updated_data["price"]
            discount = updated_data["discount"]
            updated_data["finalPrice"] = round(price - (price * discount / 100), 2)

        result = products_collection.update_one({"id": product_id}, {"$set": updated_data})

        if result.matched_count == 0:
            return jsonify({"error": "❌ المنتج غير موجود"}), 404

        return jsonify({"message": "✅ تم تحديث المنتج بنجاح"}), 200

    except Exception as e:
        return jsonify({"error": f"❌ خطأ أثناء تحديث المنتج: {str(e)}"}), 500

# Place order API
@app.route('/api/place_order', methods=['POST'])
def place_order():
    try:
        order_data = request.json
        if not order_data:
            return jsonify({"error": "❌ بيانات الطلب غير صالحة"}), 400

        # إضافة معرف فريد للطلب
        order_data["_id"] = str(ObjectId())

        # حفظ الطلب في قاعدة البيانات
        orders_collection.insert_one(order_data)

        return jsonify({"message": "✅ تم تقديم الطلب بنجاح!"}), 200
    except Exception as e:
        logger.error(f"❌ فشل في تقديم الطلب: {e}")
        return jsonify({"error": "❌ فشل في تقديم الطلب."}), 500

# Download Excel API
@app.route('/api/download_excel', methods=['GET'])
def download_excel():
    try:
        file_path = export_products_to_excel()
        if not file_path:
            return jsonify({"error": "❌ لا توجد منتجات للتصدير"}), 404
        return send_from_directory(".", "products.xlsx", as_attachment=True)
    except Exception as e:
        logger.error(f"❌ فشل في تحميل ملف Excel: {e}")
        return jsonify({"error": "❌ فشل في تحميل ملف Excel."}), 500

@app.route('/cart')
def cart():
    return render_template('cart.html')  # تم تصحيح علامات الاقتباس

@app.route('/checkout')
def checkout():
    return render_template('checkout.html')  # تم تصحيح علامات الاقتباس

@app.route('/api/store_cart', methods=['POST'])
def store_cart():
    try:
        data = request.get_json()
        print("البيانات المستلمة:", data)
        return jsonify({"message": "تم إضافة العنصر إلى السلة بنجاح!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/order_confirmation')
def order_confirmation():
    return render_template('order_confirmation.html')  # تم تصحيح علامات الاقتباس

# Get all orders
@app.route('/api/orders', methods=['GET'])
def get_orders():
    try:
        orders = list(orders_collection.find({}, {"_id": 0}))
        for order in orders:
            if "cart" in order:  # إذا كان الطلب يحتوي على "cart"
                order["items"] = order.pop("cart")  # تحويل "cart" إلى "items"
        return jsonify(orders), 200
    except Exception as e:
        logger.error(f"❌ فشل في جلب الطلبات: {e}")
        return jsonify({"error": "❌ فشل في جلب الطلبات."}), 500
@app.route('/api/orders/<order_id>', methods=['GET'])
def get_order(order_id):
    try:
        order = orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return jsonify({"error": "❌ لم يتم العثور على الطلب"}), 404

        # تحويل _id إلى string ليتم إرجاعه بشكل صحيح
        order["_id"] = str(order["_id"])
        return jsonify(order), 200
    except Exception as e:
        logger.error(f"❌ فشل في جلب الطلب: {e}")
        return jsonify({"error": "❌ فشل في جلب الطلب."}), 500


# Update order status
@app.route('/api/orders/<order_id>', methods=['PUT'])
def update_order_status(order_id):
    try:
        data = request.json
        if not data or "status" not in data:
            return jsonify({"error": "❌ بيانات غير صالحة"}), 400

        result = orders_collection.update_one(
            {"_id": ObjectId(order_id)},  # ✅ استخدام ObjectId
            {"$set": {"status": data["status"]}}
        )

        if result.matched_count == 0:
            return jsonify({"error": "❌ لم يتم العثور على الطلب"}), 404

        return jsonify({"message": "✅ تم تحديث حالة الطلب بنجاح"}), 200
    except Exception as e:
        logger.error(f"❌ فشل في تحديث حالة الطلب: {e}")
        return jsonify({"error": "❌ فشل في تحديث حالة الطلب."}), 500

# Update order details
@app.route('/api/orders/<order_id>', methods=['PUT'])
def update_order(order_id):
    try:
        data = request.json
        if not data:
            return jsonify({"error": "❌ بيانات غير صالحة"}), 400

        updated_data = {}
        for key in ["status", "items", "totalPrice", "customerName", "customerEmail", "shippingAddress"]:
            if key in data:
                updated_data[key] = data[key]

        result = orders_collection.update_one(
            {"_id": ObjectId(order_id)},  # ✅ استخدام ObjectId
            {"$set": updated_data}
        )

        if result.matched_count == 0:
            return jsonify({"error": "❌ لم يتم العثور على الطلب"}), 404

        return jsonify({"message": "✅ تم تحديث الطلب بنجاح"}), 200
    except Exception as e:
        logger.error(f"❌ فشل في تحديث الطلب: {e}")
        return jsonify({"error": f"❌ خطأ أثناء تحديث الطلب: {str(e)}"}), 500


# Delete a single order
@app.route('/api/orders/<order_id>', methods=['DELETE'])
def delete_order(order_id):
    try:
        result = orders_collection.delete_one({'_id': ObjectId(order_id)})  # ✅ استخدام ObjectId
        
        if result.deleted_count > 0:
            return jsonify({'message': '✅ تم حذف الطلب بنجاح'}), 200
        else:
            return jsonify({'error': '❌ الطلب غير موجود'}), 404
    except Exception as e:
        logger.error(f"❌ فشل في حذف الطلب: {e}")
        return jsonify({"error": "❌ فشل في حذف الطلب."}), 500

def delete_all_orders():
    try:
        result = orders_collection.delete_many({})
        return jsonify({"message": f"✅ تم حذف {result.deleted_count} طلب بنجاح"}), 200
    except Exception as e:
        logger.error(f"❌ فشل في حذف جميع الطلبات: {e}")
        return jsonify({"error": "❌ فشل في حذف جميع الطلبات."}), 500

@app.route('/static/img/uploads/<path:filename>')
def uploaded_images(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)
@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        # هنا يمكنك معالجة بيانات النموذج المُرسلة
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")
        # قم بتخزين أو إرسال البيانات كما تراه مناسباً
        logger.info(f"استفسار جديد من {name} - {email}: {subject} - {message}")
        return render_template("support.html", success=True)
    return render_template("support.html", success=False)

# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001)

