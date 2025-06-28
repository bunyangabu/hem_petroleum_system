def migrate_customers_add_vehicle_reg():
    """Migration function for adding vehicle_reg column to existing customers table"""
    try:
        # Check if vehicle_reg column exists
        conn = get_db()
        c = conn.cursor()
        
        # Try to add the column
        try:
            c.execute("ALTER TABLE customers ADD COLUMN vehicle_reg TEXT")
            conn.commit()
            print("Added vehicle_reg column to customers table")
        except Exception as e:
            if "duplicate column name" in str(e).lower():
                print("vehicle_reg column already exists in customers table")
            else:
                print(f"Error adding vehicle_reg column: {e}")
        
        conn.close()
        print("Customer table migration completed successfully")
        
    except Exception as e:
        print(f"Error during customer migration: {str(e)}")
import os
import sqlite3
import datetime
import secrets
import hashlib
from functools import wraps
from flask import (Flask, request, session, redirect, url_for, flash,
                   render_template_string, jsonify, send_from_directory)
try:
    from escpos.printer import Usb
    ESC_POS_AVAILABLE = True
except ImportError:
    ESC_POS_AVAILABLE = False

# Import RTT operations module
from rtt_operations import add_rtt_operation_route

# ------------------- Configuration -------------------
APP_NAME = "HEM Petroleum Management System"
APP_DISPLAY_NAME = "HEM Petroleum"  # Shorter name for display with logo
DATABASE = "hem_petroleum.db"
SECRET_KEY = "your-secure-random-key"  # Replace with a strong key

# USB printer config (example: VendorID and ProductID, adjust for your printer)
USB_VENDOR_ID = 0x0416  # Change to your printer vendor id
USB_PRODUCT_ID = 0x5011 # Change to your printer product id

# Branches data (Example)
BRANCHES = [
    (1, "Kibiito", "Kibiito Town, Fort Portal", "+256-700-123456"),
    (2, "Nyakigumba", "Nyakigumba Trading Center", "+256-700-234567"),
    (3, "Rwimi", "Rwimi Town Council", "+256-700-345678"),
]

# User roles and permissions
ROLES = {
    "admin": ["all"],
    "manager": ["all"],
    "attendant": ["pump_entry", "sales_entry"],
}

# Function to ensure the static directory exists
def ensure_static_directory():
    """Creates static directory if it doesn't exist"""
    import os
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
        print(f"Created static directory at {static_dir}")
    return static_dir

# ------------------- Flask App Setup -------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Ensure static directory exists
ensure_static_directory()

# Create a default logo if it doesn't exist
def create_default_logo():
    """Creates a default SVG logo if it doesn't exist in the static directory"""
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'logo.svg')
    if not os.path.exists(logo_path):
        # Create a simple SVG logo
        default_svg = '''<svg width="200" height="100" xmlns="http://www.w3.org/2000/svg">
            <rect width="200" height="100" fill="#005599" rx="10" ry="10"/>
            <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="white" font-family="Arial" font-size="24" font-weight="bold">HEM</text>
            <text x="50%" y="75%" dominant-baseline="middle" text-anchor="middle" fill="white" font-family="Arial" font-size="16">Petroleum</text>
        </svg>'''
        
        with open(logo_path, 'w') as f:
            f.write(default_svg)
        print(f"Created default logo at {logo_path}")
    return logo_path

# Create default logo
create_default_logo()

# Route to serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files from the static directory"""
    return send_from_directory('static', filename)

# Context processor to make logo_url and app_display_name available in all templates
@app.context_processor
def inject_logo_info():
    """Add logo_url and app_display_name to all template contexts"""
    return {
        'logo_url': url_for('serve_static', filename='logo.svg'),
        'app_display_name': APP_DISPLAY_NAME,
        'app_name': APP_NAME
    }

# ------------------- DB Helpers -------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False, commit=False):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(query, args)
        if commit:
            conn.commit()
            conn.close()
            return
        rv = cur.fetchall()
        conn.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# ------------------- Database Init -------------------
def create_tables():
    conn = get_db()
    c = conn.cursor()
    
    # Branches
    c.execute("""CREATE TABLE IF NOT EXISTS branches (
                 id INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 location TEXT,
                 contact TEXT)""")
    
    # Users
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 role TEXT NOT NULL,
                 branch_id INTEGER,
                 full_name TEXT,
                 phone TEXT,
                 email TEXT,
                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(branch_id) REFERENCES branches(id))""")
    
    # Inventory
    c.execute("""CREATE TABLE IF NOT EXISTS inventory (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 category TEXT NOT NULL, -- fuel, lubricants, spare_parts
                 quantity REAL NOT NULL,
                 price REAL NOT NULL,
                 reorder_level REAL NOT NULL,
                 branch_id INTEGER NOT NULL,
                 unit TEXT NOT NULL DEFAULT 'liters',
                 supplier TEXT,
                 last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(branch_id) REFERENCES branches(id))""")
    
    # Sales
    c.execute("""CREATE TABLE IF NOT EXISTS sales (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 branch_id INTEGER NOT NULL,
                 category TEXT NOT NULL,
                 product_id INTEGER NOT NULL,
                 quantity REAL NOT NULL,
                 unit_price REAL NOT NULL,
                 total_price REAL NOT NULL,
                 discount REAL DEFAULT 0,
                 payment_method TEXT NOT NULL,
                 customer_name TEXT,
                 customer_id INTEGER,
                 pump_number INTEGER,
                 sale_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                 employee_id INTEGER,
                 receipt_number TEXT,
                 notes TEXT,
                 FOREIGN KEY(branch_id) REFERENCES branches(id),
                 FOREIGN KEY(employee_id) REFERENCES users(id),
                 FOREIGN KEY(product_id) REFERENCES inventory(id),
                 FOREIGN KEY(customer_id) REFERENCES customers(id))""")
    
    # Pumps
    c.execute("""CREATE TABLE IF NOT EXISTS pumps (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 pump_number INTEGER NOT NULL,
                 branch_id INTEGER NOT NULL,
                 product_id INTEGER,
                 calibration_date TEXT,
                 calibration_due TEXT,
                 maintenance_log TEXT,
                 last_maintenance TEXT,
                 next_maintenance TEXT,
                 status TEXT DEFAULT 'active',
                 FOREIGN KEY(branch_id) REFERENCES branches(id),
                 FOREIGN KEY(product_id) REFERENCES inventory(id))""")
    
    # Customers
    c.execute("""CREATE TABLE IF NOT EXISTS customers (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 phone TEXT,
                 email TEXT,
                 address TEXT,
                 vehicle_reg TEXT,
                 customer_type TEXT DEFAULT 'retail', -- retail, wholesale, corporate
                 branch_id INTEGER NOT NULL,
                 outstanding_balance REAL DEFAULT 0,
                 credit_limit REAL DEFAULT 0,
                 tax_id TEXT,
                 notes TEXT,
                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(branch_id) REFERENCES branches(id))""")
    
    # Customer Transactions
    c.execute("""CREATE TABLE IF NOT EXISTS customer_transactions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 customer_id INTEGER NOT NULL,
                 transaction_type TEXT NOT NULL, -- sale, payment
                 amount REAL NOT NULL,
                 balance REAL NOT NULL,
                 reference TEXT,
                 notes TEXT,
                 transaction_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                 employee_id INTEGER,
                 FOREIGN KEY(customer_id) REFERENCES customers(id),
                 FOREIGN KEY(employee_id) REFERENCES users(id))""")
    
    # Suppliers
    c.execute("""CREATE TABLE IF NOT EXISTS suppliers (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 contact_person TEXT,
                 phone TEXT,
                 email TEXT,
                 address TEXT,
                 products_supplied TEXT,
                 tax_id TEXT,
                 notes TEXT)""")
    
    # Fuel Deliveries
    c.execute("""CREATE TABLE IF NOT EXISTS fuel_deliveries (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 branch_id INTEGER NOT NULL,
                 supplier_id INTEGER,
                 product_id INTEGER NOT NULL,
                 quantity REAL NOT NULL,
                 unit_price REAL NOT NULL,
                 total_cost REAL NOT NULL,
                 delivery_date TEXT NOT NULL,
                 received_by INTEGER,
                 invoice_number TEXT,
                 notes TEXT,
                 FOREIGN KEY(branch_id) REFERENCES branches(id),
                 FOREIGN KEY(supplier_id) REFERENCES suppliers(id),
                 FOREIGN KEY(product_id) REFERENCES inventory(id),
                 FOREIGN KEY(received_by) REFERENCES users(id))""")
    
    # Expenses
    c.execute("""CREATE TABLE IF NOT EXISTS expenses (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 branch_id INTEGER NOT NULL,
                 category TEXT NOT NULL,
                 amount REAL NOT NULL,
                 description TEXT,
                 expense_date TEXT NOT NULL,
                 recorded_by INTEGER,
                 receipt_number TEXT,
                 FOREIGN KEY(branch_id) REFERENCES branches(id),
                 FOREIGN KEY(recorded_by) REFERENCES users(id))""")
    
    # Sync queue
    c.execute("""CREATE TABLE IF NOT EXISTS sync_queue (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 table_name TEXT NOT NULL,
                 record_id INTEGER NOT NULL,
                 record_data TEXT NOT NULL,
                 action TEXT NOT NULL,
                 synced INTEGER DEFAULT 0,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    
    # Audit logs (attendant logs)
    c.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 action TEXT NOT NULL,
                 details TEXT,
                 ip_address TEXT,
                 user_agent TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 branch_id INTEGER,
                 FOREIGN KEY(user_id) REFERENCES users(id),
                 FOREIGN KEY(branch_id) REFERENCES branches(id))""")
    
    # Return to Tank (RTT) operations
    c.execute("""CREATE TABLE IF NOT EXISTS rtt_operations (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 branch_id INTEGER NOT NULL,
                 product_id INTEGER NOT NULL,
                 pump_number INTEGER NOT NULL,
                 quantity REAL NOT NULL,
                 reason TEXT,
                 employee_id INTEGER,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(branch_id) REFERENCES branches(id),
                 FOREIGN KEY(product_id) REFERENCES inventory(id),
                 FOREIGN KEY(employee_id) REFERENCES users(id))""")
    
    conn.commit()
    conn.close()
    
    # Insert branches if empty
    existing = query_db("SELECT * FROM branches")
    if not existing:
        conn = get_db()
        c = conn.cursor()
        c.executemany("INSERT INTO branches (id, name, location, contact) VALUES (?, ?, ?, ?)", BRANCHES)
        conn.commit()
        conn.close()
        
    # Create default admin user if no users exist
    admin_exists = query_db("SELECT * FROM users WHERE username = ?", ("admin",), one=True)
    if not admin_exists:
        create_user("admin", "Admin123", "admin", None, "System Administrator")
        print("Default admin user created. Username: admin, Password: Admin123")
        
    # Perform migrations
    migrate_customers_add_vehicle_reg()
    
    # Synchronize suppliers from inventory to suppliers table
    sync_suppliers_from_inventory()

# ------------------- Authentication -------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_role" not in session:
                flash("Access denied: login required.", "danger")
                return redirect(url_for("login"))
            if "all" not in allowed_roles and session.get("user_role") not in allowed_roles:
                flash("Access denied: insufficient permissions.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return decorator

def hash_password(pw):
    salt = secrets.token_hex(8)
    return salt + hashlib.sha256((pw + salt).encode()).hexdigest()

def verify_password(pw, hashed):
    if not hashed or len(hashed) < 16:
        return False
    salt = hashed[:16]
    return hashed == salt + hashlib.sha256((pw + salt).encode()).hexdigest()

# ------------------- User Management -------------------
def create_user(username, password, role, branch_id=None, full_name=None, phone=None, email=None):
    hashed = hash_password(password)
    try:
        query_db("""INSERT INTO users 
                    (username, password, role, branch_id, full_name, phone, email) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                 (username, hashed, role, branch_id, full_name, phone, email), commit=True)
        return True
    except sqlite3.IntegrityError:
        return False

# ------------------- Customer Helper -------------------
def find_or_create_customer(name, phone=None, vehicle_reg=None, branch_id=None):
    """Find existing customer or create new one during sales"""
    if not name or not name.strip():
        return None
    
    name = name.strip()
    
    # Try to find existing customer by name and phone (if provided)
    if phone and phone.strip():
        customer = query_db("""
            SELECT * FROM customers 
            WHERE LOWER(name) = LOWER(?) AND phone = ? AND branch_id = ?
        """, (name, phone.strip(), branch_id), one=True)
    else:
        customer = query_db("""
            SELECT * FROM customers 
            WHERE LOWER(name) = LOWER(?) AND branch_id = ?
        """, (name, branch_id), one=True)
    
    if customer:
        # Update vehicle registration if provided and different
        if vehicle_reg and vehicle_reg.strip() and customer.get('vehicle_reg') != vehicle_reg.strip():
            query_db("""
                UPDATE customers SET vehicle_reg = ?
                WHERE id = ?
            """, (vehicle_reg.strip(), customer['id']), commit=True)
            customer = dict(customer)
            customer['vehicle_reg'] = vehicle_reg.strip()
        return customer
    
    # Create new customer
    try:
        query_db("""
            INSERT INTO customers (name, phone, vehicle_reg, branch_id, customer_type)
            VALUES (?, ?, ?, ?, 'retail')
        """, (name, phone.strip() if phone else None, 
              vehicle_reg.strip() if vehicle_reg else None, branch_id), commit=True)
        
        # Get the newly created customer
        if phone and phone.strip():
            customer = query_db("""
                SELECT * FROM customers 
                WHERE LOWER(name) = LOWER(?) AND phone = ? AND branch_id = ?
            """, (name, phone.strip(), branch_id), one=True)
        else:
            customer = query_db("""
                SELECT * FROM customers 
                WHERE LOWER(name) = LOWER(?) AND branch_id = ?
                ORDER BY id DESC LIMIT 1
            """, (name, branch_id), one=True)
        
        return customer
    except Exception as e:
        print(f"Error creating customer: {e}")
        return None

# ------------------- Branch Utilities -------------------
def get_branch_info(branch_id):
    """Get detailed information about a specific branch"""
    branch_row = query_db("SELECT * FROM branches WHERE id = ?", (branch_id,), one=True)
    if not branch_row:
        return None
    
    # Convert Row object to dictionary
    branch = dict(branch_row)
    
    # Sales metrics
    sales = query_db("""
        SELECT 
            SUM(total_price) as total_sales,
            COUNT(*) as transaction_count,
            SUM(CASE WHEN strftime('%Y-%m-%d', sale_date) = date('now') THEN total_price ELSE 0 END) as today_sales,
            SUM(CASE WHEN strftime('%Y-%m', sale_date) = strftime('%Y-%m', 'now') THEN total_price ELSE 0 END) as monthly_sales
        FROM sales
        WHERE branch_id = ?
    """, (branch_id,), one=True)
    
    # Inventory metrics
    inventory = query_db("""
        SELECT 
            COUNT(*) as item_count,
            SUM(quantity * price) as inventory_value,
            SUM(CASE WHEN quantity <= reorder_level THEN 1 ELSE 0 END) as low_stock_count
        FROM inventory
        WHERE branch_id = ?
    """, (branch_id,), one=True)
    
    # Employee count
    employees = query_db("""
        SELECT COUNT(*) as count
        FROM users
        WHERE branch_id = ?
    """, (branch_id,), one=True)
    
    # Add metrics to branch data
    # Ensure we handle None values properly
    branch['metrics'] = {
        'sales': {
            'total_sales': sales['total_sales'] if sales['total_sales'] is not None else 0,
            'transaction_count': sales['transaction_count'] if sales['transaction_count'] is not None else 0,
            'today_sales': sales['today_sales'] if sales['today_sales'] is not None else 0,
            'monthly_sales': sales['monthly_sales'] if sales['monthly_sales'] is not None else 0
        },
        'inventory': {
            'item_count': inventory['item_count'] if inventory['item_count'] is not None else 0,
            'inventory_value': inventory['inventory_value'] if inventory['inventory_value'] is not None else 0,
            'low_stock_count': inventory['low_stock_count'] if inventory['low_stock_count'] is not None else 0
        },
        'employee_count': employees['count'] if employees['count'] is not None else 0
    }
    
    return branch

def update_user(user_id, username=None, role=None, branch_id=None, full_name=None, phone=None, email=None):
    # Check if user is trying to modify their own role
    if role and user_id == session.get("user_id") and session.get("user_role") == "admin" and role != "admin":
        # Prevent admin from downgrading their own role
        return False
        
    updates = []
    args = []
    if username:
        updates.append("username = ?")
        args.append(username)
    if role:
        updates.append("role = ?")
        args.append(role)
    if branch_id is not None:
        updates.append("branch_id = ?")
        args.append(branch_id)
    if full_name:
        updates.append("full_name = ?")
        args.append(full_name)
    if phone:
        updates.append("phone = ?")
        args.append(phone)
    if email:
        updates.append("email = ?")
        args.append(email)
    
    if not updates:
        return False
    
    args.append(user_id)
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    try:
        query_db(query, args, commit=True)
        return True
    except Exception:
        return False

def change_password(user_id, new_password):
    hashed = hash_password(new_password)
    try:
        query_db("UPDATE users SET password = ? WHERE id = ?", 
                 (hashed, user_id), commit=True)
        return True
    except Exception:
        return False

# ------------------- Session Management -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = query_db("""
            SELECT u.*, b.name as branch_name 
            FROM users u
            LEFT JOIN branches b ON u.branch_id = b.id
            WHERE u.username = ?
        """, (username,), one=True)
        
        if user and verify_password(password, user["password"]):
            session["user_id"] = user["id"]
            session["user_role"] = user["role"]
            session["branch_id"] = user["branch_id"]
            session["branch_name"] = user["branch_name"] if user["branch_id"] else "No Branch"
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            
            # Log login
            add_audit_log(
                user["id"], 
                "User logged in", 
                f"Successful login for {username}",
                request.remote_addr,
                request.user_agent.string,
                user["branch_id"]
            )
            
            flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
            next_url = request.args.get('next') or url_for('dashboard')
            return redirect(next_url)
        
        # Log failed attempt
        add_audit_log(
            None, 
            "Failed login attempt", 
            f"Failed login for username: {username}",
            request.remote_addr,
            request.user_agent.string,
            None
        )
        flash("Invalid username or password", "danger")
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-card {
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            max-width: 450px;
        }
        .login-header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 25px;
            text-align: center;
        }
        .login-body {
            padding: 30px;
            background: white;
        }
        .form-control {
            padding: 12px 15px;
            border-radius: 8px;
        }
        .btn-login {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            border: none;
            padding: 12px;
            font-weight: 600;
            letter-spacing: 1px;
        }
        .logo {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8 col-lg-6">
            <div class="login-card">
                <div class="login-header">
                    <div class="logo">
                        <img src="{{ logo_url }}" alt="{{app_name}}" style="height: 60px; margin-bottom: 10px;">
                        <div style="font-size: 22px; font-weight: bold;">{{ app_display_name }}</div>
                    </div>
                    <p>Fuel Management System</p>
                </div>
                <div class="login-body">
                    {% with messages = get_flashed_messages(with_categories=true) %}
                        {% if messages %}
                            {% for cat, msg in messages %}
                                <div class="alert alert-{{cat}} alert-dismissible fade show">{{msg}}
                                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                </div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    <form method="post">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-user"></i></span>
                                <input class="form-control" type="text" id="username" name="username" required autofocus>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                <input class="form-control" type="password" id="password" name="password" required>
                            </div>
                        </div>
                        <div class="d-grid mb-3">
                            <button class="btn btn-primary btn-login" type="submit">
                                <i class="fas fa-sign-in-alt me-2"></i>Login
                            </button>
                        </div>
                        <div class="text-center">
                            <small class="text-muted">© {{current_year}} HEM Petroleum. All rights reserved.</small>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, current_year=datetime.datetime.now().year)

@app.route("/logout")
@login_required
def logout():
    # Log logout
    add_audit_log(
        session["user_id"], 
        "User logged out", 
        f"{session['username']} logged out",
        request.remote_addr,
        request.user_agent.string,
        session["branch_id"]
    )
    
    session.clear()
    flash("You have been logged out successfully", "info")
    return redirect(url_for("login"))

# ------------------- Dashboard -------------------
@app.route("/")
@login_required
def dashboard():
    branch_id = session.get("branch_id")
    user_role = session.get("user_role")
    
    # Get all branches for admin users (for branch selector)
    all_branches = []
    if user_role == 'admin':
        branch_rows = query_db("SELECT * FROM branches ORDER BY name")
        all_branches = [dict(row) for row in branch_rows]
    
    # Dashboard stats
    stats = {
        "total_sales": 0,
        "transaction_count": 0,
        "today_sales": 0,
        "monthly_sales": 0,
        "low_stock": 0,
        "rtt_operations": 0,
        "today_rtt": 0,
        "rtt_quantity": 0,
    }
    
    # Initialize default variables
    recent_sales = []
    recent_activities = []
    
    if user_role in ["admin", "manager"]:
        # Sales summary
        sales_stats = query_db("""
            SELECT 
                SUM(total_price) as total_sales,
                COUNT(*) as transaction_count,
                SUM(CASE WHEN strftime('%Y-%m-%d', sale_date) = date('now') THEN total_price ELSE 0 END) as today_sales,
                SUM(CASE WHEN strftime('%Y-%m', sale_date) = strftime('%Y-%m', 'now') THEN total_price ELSE 0 END) as monthly_sales
            FROM sales
            WHERE branch_id = ?
        """, (branch_id,), one=True)
        
        stats.update({
            "total_sales": sales_stats["total_sales"] or 0,
            "transaction_count": sales_stats["transaction_count"] or 0,
            "today_sales": sales_stats["today_sales"] or 0,
            "monthly_sales": sales_stats["monthly_sales"] or 0,
        })
        
        # Inventory alerts
        low_stock = query_db("""
            SELECT COUNT(*) as count 
            FROM inventory 
            WHERE branch_id = ? AND quantity <= reorder_level
        """, (branch_id,), one=True)
        
        stats["low_stock"] = low_stock["count"] or 0
        
        # RTT metrics
        rtt_metrics = query_db("""
            SELECT 
                COUNT(*) as total_operations,
                SUM(CASE WHEN strftime('%Y-%m-%d', timestamp) = date('now') THEN 1 ELSE 0 END) as today_operations,
                SUM(quantity) as total_quantity
            FROM rtt_operations
            WHERE branch_id = ?
        """, (branch_id,), one=True)
        
        stats.update({
            "rtt_operations": rtt_metrics["total_operations"] or 0,
            "today_rtt": rtt_metrics["today_operations"] or 0,
            "rtt_quantity": rtt_metrics["total_quantity"] or 0,
        })
        
        # Recent transactions
        recent_sales = query_db("""
            SELECT s.id, s.sale_date, i.name as product, s.quantity, s.total_price, u.username as employee
            FROM sales s
            JOIN inventory i ON s.product_id = i.id
            LEFT JOIN users u ON s.employee_id = u.id
            WHERE s.branch_id = ?
            ORDER BY s.sale_date DESC
            LIMIT 5
        """, (branch_id,))
        
        # Recent activities
        recent_activities = query_db("""
            SELECT a.timestamp, a.action, u.username 
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.branch_id = ?
            ORDER BY a.timestamp DESC
            LIMIT 5
        """, (branch_id,))
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .sidebar-nav-dropdown {
            padding-left: 1.5rem;
            list-style: none;
            background-color: rgba(0, 0, 0, 0.1);
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-in-out;
        }
        .sidebar-nav-dropdown.show {
            max-height: 500px;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .stat-card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .stat-icon {
            font-size: 2.5rem;
            opacity: 0.7;
        }
        .stat-value {
            font-size: 1.8rem;
            font-weight: 600;
        }
        .stat-label {
            font-size: 0.9rem;
            color: #6c757d;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .table-responsive {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.05);
        }
        .table th {
            background-color: #f8f9fa;
            border-bottom-width: 1px;
        }
        .badge {
            padding: 0.35em 0.65em;
            font-weight: 500;
        }
        .alert {
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('dashboard') else '' }}">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('quick_sale') else '' }}">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('inventory') else '' }}">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('sales') else '' }}">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('pumps') else '' }}">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('rtt_operation') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('rtt_operation') else '' }}">
                    <i class="fas fa-exchange-alt"></i> Return to Tank
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('customers') else '' }}">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('employees') else '' }}">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('reports') else '' }}">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('deliveries') else '' }}">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('expenses') else '' }}">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link {{ 'active' if request.path == url_for('backup') else '' }}">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Page Content -->
        <div class="container-fluid">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <!-- Current Branch Banner -->
            <div class="alert alert-info d-flex justify-content-between align-items-center mb-4">
                <div>
                    <i class="fas fa-building me-2"></i>
                    <strong>Current Branch:</strong> {{ session.branch_name }}
                </div>
                {% if user_role == 'admin' %}
                <div class="branch-selector">
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-primary dropdown-toggle" 
                                type="button" id="branchDropdown" data-bs-toggle="dropdown">
                            <i class="fas fa-exchange-alt me-1"></i> Switch Branch
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="branchDropdown">
                            {% for branch in all_branches %}
                            <li>
                                <a class="dropdown-item {% if branch.id == session.branch_id %}active{% endif %}" 
                                   href="{{ url_for('switch_branch', branch_id=branch.id) }}">
                                    {{ branch.name }}
                                </a>
                            </li>
                            {% endfor %}
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <a class="dropdown-item" href="{{ url_for('branch_management') }}">
                                    <i class="fas fa-cog me-2"></i>Manage All Branches
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
                {% endif %}
            </div>

            <h2 class="mb-4">Dashboard</h2>
            
            <!-- Stats Cards -->
            <div class="row mb-4">
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stat-card card border-left-primary h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="stat-label text-primary text-uppercase mb-1">
                                        Today's Sales
                                    </div>
                                    <div class="stat-value text-gray-800">
                                        UGX {{ "{:,.0f}".format(stats.today_sales) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-calendar stat-icon text-primary"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stat-card card border-left-success h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="stat-label text-success text-uppercase mb-1">
                                        Monthly Sales
                                    </div>
                                    <div class="stat-value text-gray-800">
                                        UGX {{ "{:,.0f}".format(stats.monthly_sales) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-dollar-sign stat-icon text-success"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stat-card card border-left-info h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="stat-label text-info text-uppercase mb-1">
                                        Transactions
                                    </div>
                                    <div class="stat-value text-gray-800">
                                        {{ stats.transaction_count }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-clipboard-list stat-icon text-info"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stat-card card border-left-warning h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="stat-label text-warning text-uppercase mb-1">
                                        Low Stock Items
                                    </div>
                                    <div class="stat-value text-gray-800">
                                        {{ stats.low_stock }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-exclamation-triangle stat-icon text-warning"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- RTT Card -->
            <div class="row mb-4">
                <div class="col-xl-6 mb-4">
                    <div class="card border-left-danger h-100 py-2">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h5 class="text-danger">Return to Tank (RTT) Operations</h5>
                                <a href="{{ url_for('rtt_operation') }}" class="btn btn-sm btn-warning">
                                    <i class="fas fa-exchange-alt me-1"></i> Record RTT
                                </a>
                            </div>
                            <div class="row">
                                <div class="col-md-4 text-center">
                                    <div class="h4">{{ stats.today_rtt }}</div>
                                    <div class="small text-muted">Today's Returns</div>
                                </div>
                                <div class="col-md-4 text-center">
                                    <div class="h4">{{ stats.rtt_operations }}</div>
                                    <div class="small text-muted">Total RTT Operations</div>
                                </div>
                                <div class="col-md-4 text-center">
                                    <div class="h4">{{ "{:.1f}".format(stats.rtt_quantity or 0) }}</div>
                                    <div class="small text-muted">Total Liters Returned</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            
            <!-- Recent Transactions -->
            <div class="row">
                <div class="col-lg-6 mb-4">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h6 class="m-0 font-weight-bold text-primary">Recent Transactions</h6>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Product</th>
                                            <th>Amount</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for sale in recent_sales %}
                                        <tr>
                                            <td>{{ sale.sale_date|datetimeformat }}</td>
                                            <td>{{ sale.product }}</td>
                                            <td>UGX {{ "{:,.0f}".format(sale.total_price) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="3" class="text-center">No recent transactions</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Activities -->
                <div class="col-lg-6 mb-4">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h6 class="m-0 font-weight-bold text-primary">Recent Activities</h6>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>User</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for activity in recent_activities %}
                                        <tr>
                                            <td>{{ activity.timestamp|datetimeformat }}</td>
                                            <td>{{ activity.username }}</td>
                                            <td>{{ activity.action }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="3" class="text-center">No recent activities</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Activate sidebar dropdowns
        document.querySelectorAll('.sidebar-nav-link').forEach(link => {
            link.addEventListener('click', function() {
                document.querySelectorAll('.sidebar-nav-link').forEach(l => l.classList.remove('active'));
                this.classList.add('active');
            });
        });
    </script>
</body>
</html>
""", app_name=APP_NAME, stats=stats, recent_sales=recent_sales or [], 
   recent_activities=recent_activities or [], user_role=user_role, all_branches=all_branches or [])

# ------------------- Quick Sale -------------------
@app.route("/quick-sale", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager", "attendant"])
def quick_sale():
    branch_id = session.get("branch_id")
    
    if request.method == "POST":
        try:
            product_id = int(request.form.get("product_id"))
            quantity = float(request.form.get("quantity"))
            payment_method = request.form.get("payment_method", "cash")
            
            # Get customer information
            customer_name = request.form.get("customer_name", "").strip()
            customer_phone = request.form.get("customer_phone", "").strip()
            vehicle_reg = request.form.get("vehicle_reg", "").strip()
            
            customer_id = None
            if customer_name:
                # Find or create customer
                customer = find_or_create_customer(customer_name, customer_phone, vehicle_reg, branch_id)
                if customer:
                    customer_id = customer['id']
                    customer_name = customer['name']  # Use the stored name format
            
            # Get product details
            product = query_db("SELECT * FROM inventory WHERE id = ? AND branch_id = ?", 
                             (product_id, branch_id), one=True)
            
            if not product:
                flash("Invalid product selected", "danger")
                return redirect(url_for("quick_sale"))
            
            if quantity <= 0:
                flash("Quantity must be greater than zero", "danger")
                return redirect(url_for("quick_sale"))
                
            if product["quantity"] < quantity:
                flash(f"Insufficient stock. Only {product['quantity']} {product['unit']} available", "danger")
                return redirect(url_for("quick_sale"))
            
            # Calculate total
            total_price = product["price"] * quantity
            
            # Generate receipt number
            receipt_number = f"RCPT-{datetime.datetime.now().strftime('%Y%m%d')}-{query_db('SELECT COUNT(*) FROM sales WHERE branch_id = ? AND date(sale_date) = date()', (branch_id,), one=True)[0] + 1}"
            
            # Record sale
            query_db("""
                INSERT INTO sales 
                (branch_id, category, product_id, quantity, unit_price, total_price, payment_method, 
                 customer_name, customer_id, employee_id, receipt_number, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                branch_id, 
                product["category"], 
                product_id, 
                quantity, 
                product["price"], 
                total_price, 
                payment_method,
                customer_name if customer_name else None,
                customer_id,
                session["user_id"],
                receipt_number,
                f"Vehicle: {vehicle_reg}" if vehicle_reg else None
            ), commit=True)
            
            # Update inventory
            query_db("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", 
                     (quantity, product_id), commit=True)
            
            # Get the sale record for receipt
            sale = query_db("SELECT * FROM sales WHERE receipt_number = ?", (receipt_number,), one=True)
            
            # Print receipt
            print_receipt(sale, product)
            
            success_msg = f"Sale recorded successfully. Receipt: {receipt_number}"
            if customer_name:
                success_msg += f" | Customer: {customer_name}"
            if vehicle_reg:
                success_msg += f" | Vehicle: {vehicle_reg}"
            
            flash(success_msg, "success")
            return redirect(url_for("quick_sale"))
            
        except Exception as e:
            flash(f"Error processing sale: {str(e)}", "danger")
            return redirect(url_for("quick_sale"))
    
    # Get available products
    products = query_db("""
        SELECT * FROM inventory 
        WHERE branch_id = ? AND quantity > 0
        ORDER BY category, name
    """, (branch_id,))
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Quick Sale - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .sale-container {
            max-width: 800px;
            margin: 0 auto;
        }
        .product-card {
            cursor: pointer;
            transition: all 0.3s;
            border-radius: 10px;
        }
        .product-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .product-card.selected {
            border: 2px solid #1e3c72;
            background-color: rgba(30, 60, 114, 0.05);
        }
        .payment-methods .btn {
            border-radius: 20px;
        }
        #totalDisplay {
            font-size: 1.5rem;
            font-weight: bold;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link active">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Quick Sale</h2>
                <div class="d-flex align-items-center">
                    <a href="{{ url_for('rtt_operation') }}" class="btn btn-warning me-3">
                        <i class="fas fa-exchange-alt me-2"></i>Return to Tank
                    </a>
                    <div>
                        <span class="badge bg-primary">Branch: {{ session.branch_name or 'N/A' }}</span>
                        <span class="badge bg-secondary ms-2">User: {{ session.username }}</span>
                    </div>
                </div>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="sale-container">
                <form method="post" id="saleForm">
                    <!-- Product Selection -->
                    <div class="card mb-4">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Select Product</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                {% for product in products %}
                                <div class="col-md-4 mb-3">
                                    <div class="product-card card h-100" 
                                         onclick="selectProduct({{ product.id }}, {{ product.price }}, '{{ product.unit }}')"
                                         id="product-{{ product.id }}">
                                        <div class="card-body">
                                            <h6 class="card-title">{{ product.name }}</h6>
                                            <p class="card-text text-muted mb-1">{{ product.category|title }}</p>
                                            <p class="card-text mb-1">
                                                <span class="badge bg-info">UGX {{ "{:,.0f}".format(product.price) }}/{{ product.unit }}</span>
                                            </p>
                                            <p class="card-text">
                                                <small class="text-muted">Stock: {{ product.quantity }} {{ product.unit }}</small>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                                {% else %}
                                <div class="col-12">
                                    <div class="alert alert-warning">No products available for sale</div>
                                </div>
                                {% endfor %}
                            </div>
                            <input type="hidden" name="product_id" id="selectedProductId" required>
                        </div>
                    </div>
                    
                    <!-- Quantity and Total -->
                    <div class="card mb-4">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Quantity & Total</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="quantity" class="form-label">Quantity</label>
                                    <div class="input-group">
                                        <input type="number" step="any" min="0.01" class="form-control" 
                                               id="quantity" name="quantity" required 
                                               oninput="calculateTotal()">
                                        <span class="input-group-text" id="unitDisplay">-</span>
                                    </div>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Total Amount</label>
                                    <div class="input-group">
                                        <span class="input-group-text">UGX</span>
                                        <input type="text" class="form-control bg-light" 
                                               id="totalDisplay" value="0" readonly>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Payment Method -->
                    <div class="card mb-4">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Payment Method</h5>
                        </div>
                        <div class="card-body">
                            <div class="payment-methods btn-group w-100" role="group">
                                <input type="radio" class="btn-check" name="payment_method" 
                                       id="cash" value="cash" autocomplete="off" checked>
                                <label class="btn btn-outline-primary" for="cash">
                                    <i class="fas fa-money-bill-wave me-2"></i>Cash
                                </label>
                                
                                <input type="radio" class="btn-check" name="payment_method" 
                                       id="mobile_money" value="mobile_money" autocomplete="off">
                                <label class="btn btn-outline-primary" for="mobile_money">
                                    <i class="fas fa-mobile-alt me-2"></i>Mobile Money
                                </label>
                                
                                <input type="radio" class="btn-check" name="payment_method" 
                                       id="credit" value="credit" autocomplete="off">
                                <label class="btn btn-outline-primary" for="credit">
                                    <i class="fas fa-credit-card me-2"></i>Credit
                                </label>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Customer Information -->
                    <div class="card mb-4">
                        <div class="card-header bg-info text-white">
                            <h5 class="mb-0">Customer Information (Optional)</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="customer_name" class="form-label">Customer Name</label>
                                    <input type="text" class="form-control" 
                                           id="customer_name" name="customer_name" 
                                           placeholder="Enter customer name">
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="customer_phone" class="form-label">Phone Number</label>
                                    <input type="tel" class="form-control" 
                                           id="customer_phone" name="customer_phone" 
                                           placeholder="Enter phone number">
                                </div>
                            </div>
                            <div class="mb-3">
                                <label for="vehicle_reg" class="form-label">Vehicle Registration</label>
                                <input type="text" class="form-control" 
                                       id="vehicle_reg" name="vehicle_reg" 
                                       placeholder="Enter vehicle registration number">
                            </div>
                            <small class="form-text text-muted">
                                <i class="fas fa-info-circle me-1"></i>
                                Adding customer information helps track sales and manage credit customers. 
                                Customers will be automatically added to the customer database.
                            </small>
                        </div>
                    </div>
                    
                    <!-- Submit Button -->
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="fas fa-check-circle me-2"></i>Complete Sale
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let selectedProductPrice = 0;
        
        function selectProduct(productId, price, unit) {
            // Update selected product UI
            document.querySelectorAll('.product-card').forEach(card => {
                card.classList.remove('selected');
            });
            document.getElementById(`product-${productId}`).classList.add('selected');
            
            // Set form values
            document.getElementById('selectedProductId').value = productId;
            document.getElementById('unitDisplay').textContent = unit;
            selectedProductPrice = price;
            
            // Recalculate total
            calculateTotal();
        }
        
        function calculateTotal() {
            const quantity = parseFloat(document.getElementById('quantity').value) || 0;
            const total = quantity * selectedProductPrice;
            document.getElementById('totalDisplay').value = total.toFixed(2);
        }
    </script>
</body>
</html>
""", app_name=APP_NAME, products=products, user_role=session.get("user_role"))

# ------------------- Inventory Management -------------------
@app.route("/inventory", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager", "attendant"])
def inventory():
    branch_id = session.get("branch_id")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            # Handle new inventory item
            try:
                name = request.form.get("name").strip()
                category = request.form.get("category")
                quantity = float(request.form.get("quantity", 0))
                price = float(request.form.get("price", 0))
                reorder_level = float(request.form.get("reorder_level", 0))
                unit = request.form.get("unit", "liters")
                supplier = request.form.get("supplier", "").strip()
                
                query_db("""
                    INSERT INTO inventory 
                    (name, category, quantity, price, reorder_level, branch_id, unit, supplier)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    name, category, quantity, price, reorder_level, branch_id, unit, supplier
                ), commit=True)
                
                flash("Inventory item added successfully", "success")
                
            except Exception as e:
                flash(f"Error adding inventory item: {str(e)}", "danger")
                
        elif action == "update":
            # Handle inventory update
            try:
                item_id = int(request.form.get("item_id"))
                quantity = float(request.form.get("quantity", 0))
                
                query_db("""
                    UPDATE inventory SET quantity = ?
                    WHERE id = ? AND branch_id = ?
                """, (quantity, item_id, branch_id), commit=True)
                
                flash("Inventory updated successfully", "success")
                
            except Exception as e:
                flash(f"Error updating inventory: {str(e)}", "danger")
                
        elif action == "delivery":
            # Handle fuel delivery
            try:
                product_id = int(request.form.get("product_id"))
                quantity = float(request.form.get("quantity", 0))
                unit_price = float(request.form.get("unit_price", 0))
                supplier_id = request.form.get("supplier_id")
                invoice_number = request.form.get("invoice_number", "").strip()
                notes = request.form.get("notes", "").strip()
                
                # Add to inventory
                query_db("""
                    UPDATE inventory SET quantity = quantity + ?
                    WHERE id = ? AND branch_id = ?
                """, (quantity, product_id, branch_id), commit=True)
                
                # Record delivery
                query_db("""
                    INSERT INTO fuel_deliveries 
                    (branch_id, supplier_id, product_id, quantity, unit_price, total_cost, 
                     delivery_date, received_by, invoice_number, notes)
                    VALUES (?, ?, ?, ?, ?, ?, date('now'), ?, ?, ?)
                """, (
                    branch_id, supplier_id, product_id, quantity, unit_price, 
                    quantity * unit_price, session["user_id"], invoice_number, notes
                ), commit=True)
                
                flash("Fuel delivery recorded and inventory updated", "success")
                
            except Exception as e:
                flash(f"Error processing delivery: {str(e)}", "danger")
                
        return redirect(url_for("inventory"))
    
    # Get inventory items
    items = query_db("""
        SELECT * FROM inventory 
        WHERE branch_id = ?
        ORDER BY category, name
    """, (branch_id,))
    
    # Get low stock items (quantity <= reorder_level)
    low_stock = query_db("""
        SELECT * FROM inventory 
        WHERE branch_id = ? AND quantity <= reorder_level
        ORDER BY quantity ASC
    """, (branch_id,))
    
    # Get suppliers for forms
    suppliers = query_db("SELECT id, name FROM suppliers ORDER BY name")
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Inventory - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .inventory-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .inventory-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .low-stock {
            border-left: 4px solid #dc3545;
        }
        .tab-content {
            padding: 20px;
            background: white;
            border-radius: 0 0 10px 10px;
            border: 1px solid #dee2e6;
            border-top: none;
        }
        .nav-tabs .nav-link.active {
            font-weight: 600;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link active">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Inventory Management</h2>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addItemModal">
                    <i class="fas fa-plus me-2"></i>Add Item
                </button>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <!-- Inventory Tabs -->
            <ul class="nav nav-tabs" id="inventoryTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="all-tab" data-bs-toggle="tab" 
                            data-bs-target="#all" type="button" role="tab">
                        All Items
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="low-stock-tab" data-bs-toggle="tab" 
                            data-bs-target="#low-stock" type="button" role="tab">
                        Low Stock <span class="badge bg-danger ms-1">{{ low_stock|length }}</span>
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="delivery-tab" data-bs-toggle="tab" 
                            data-bs-target="#delivery" type="button" role="tab">
                        Record Delivery
                    </button>
                </li>
            </ul>
            
            <div class="tab-content" id="inventoryTabsContent">
                <!-- All Items Tab -->
                <div class="tab-pane fade show active" id="all" role="tabpanel">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Name</th>
                                    <th>Category</th>
                                    <th>Quantity</th>
                                    <th>Price (UGX)</th>
                                    <th>Reorder Level</th>
                                    <th>Value</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for item in items %}
                                <tr class="{% if item.quantity <= item.reorder_level %}table-warning{% endif %}">
                                    <td>{{ item.name }}</td>
                                    <td>{{ item.category|title }}</td>
                                    <td>{{ "%.2f"|format(item.quantity) }} {{ item.unit }}</td>
                                    <td>{{ "{:,.0f}".format(item.price) }}</td>
                                    <td>{{ "%.2f"|format(item.reorder_level) }} {{ item.unit }}</td>
                                    <td>UGX {{ "{:,.0f}".format(item.quantity * item.price) }}</td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#updateModal{{ item.id }}">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                    </td>
                                </tr>
                                
                                <!-- Update Modal -->
                                <div class="modal fade" id="updateModal{{ item.id }}" tabindex="-1">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Update {{ item.name }}</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                            </div>
                                            <form method="post">
                                                <div class="modal-body">
                                                    <input type="hidden" name="action" value="update">
                                                    <input type="hidden" name="item_id" value="{{ item.id }}">
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Current Quantity</label>
                                                        <input type="number" step="0.01" class="form-control" 
                                                               name="quantity" value="{{ "%.2f"|format(item.quantity) }}" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Price</label>
                                                        <input type="number" step="0.01" class="form-control" 
                                                               name="price" value="{{ "%.2f"|format(item.price) }}" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Reorder Level</label>
                                                        <input type="number" step="0.01" class="form-control" 
                                                               name="reorder_level" value="{{ "%.2f"|format(item.reorder_level) }}" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Supplier</label>
                                                        <input type="text" class="form-control" name="supplier" list="update-supplier-list-{{ item.id }}" 
                                                               value="{{ item.supplier }}" placeholder="Select or type a new supplier">
                                                        <datalist id="update-supplier-list-{{ item.id }}">
                                                            {% for supplier in suppliers %}
                                                            <option value="{{ supplier.name }}">
                                                            {% endfor %}
                                                        </datalist>
                                                        <small class="text-muted">New suppliers will be automatically added to the system</small>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                                {% else %}
                                <tr>
                                    <td colspan="7" class="text-center">No inventory items found</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Low Stock Tab -->
                <div class="tab-pane fade" id="low-stock" role="tabpanel">
                    {% if low_stock %}
                    <div class="row">
                        {% for item in low_stock %}
                        <div class="col-md-4 mb-4">
                            <div class="inventory-card card low-stock h-100">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <h5 class="card-title">{{ item.name }}</h5>
                                        <span class="badge bg-danger">Low Stock</span>
                                    </div>
                                    <p class="card-text text-muted">{{ item.category|title }}</p>
                                    
                                    <div class="mb-2">
                                        <small class="text-muted">Current Quantity:</small>
                                        <h6 class="mb-0">{{ "%.2f"|format(item.quantity) }} {{ item.unit }}</h6>
                                    </div>
                                    
                                    <div class="mb-2">
                                        <small class="text-muted">Reorder Level:</small>
                                        <h6 class="mb-0">{{ "%.2f"|format(item.reorder_level) }} {{ item.unit }}</h6>
                                    </div>
                                    
                                    <div class="mb-2">
                                        <small class="text-muted">Price:</small>
                                        <h6 class="mb-0">UGX {{ "{:,.0f}".format(item.price) }}</h6>
                                    </div>
                                    
                                    <div class="d-grid mt-3">
                                        <button class="btn btn-sm btn-warning" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#updateModal{{ item.id }}">
                                            <i class="fas fa-edit me-2"></i>Update Stock
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i> All inventory items are above reorder levels
                    </div>
                    {% endif %}
                </div>
                
                <!-- Record Delivery Tab -->
                <div class="tab-pane fade" id="delivery" role="tabpanel">
                    <form method="post">
                        <input type="hidden" name="action" value="delivery">
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Product</label>
                                <select class="form-select" name="product_id" required>
                                    <option value="">Select Product</option>
                                    {% for item in items %}
                                    <option value="{{ item.id }}">{{ item.name }} ({{ item.category|title }})</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Supplier</label>
                                <div class="input-group">
                                    <select class="form-select" name="supplier_id" id="supplierSelect">
                                        <option value="">Select Supplier</option>
                                        {% for supplier in suppliers %}
                                        <option value="{{ supplier.id }}">{{ supplier.name }}</option>
                                        {% endfor %}
                                    </select>
                                    <button class="btn btn-outline-secondary" type="button" 
                                            data-bs-toggle="modal" data-bs-target="#addSupplierModal">
                                        <i class="fas fa-plus"></i>
                                    </button>
                                </div>
                                <small class="text-muted">Suppliers added in inventory will appear here automatically</small>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-4">
                                <label class="form-label">Quantity</label>
                                <input type="number" step="0.01" min="0.01" class="form-control" 
                                       name="quantity" required>
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">Unit Price (UGX)</label>
                                <input type="number" step="0.01" min="0" class="form-control" 
                                       name="unit_price" required>
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">Invoice Number</label>
                                <input type="text" class="form-control" name="invoice_number">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Notes</label>
                            <textarea class="form-control" name="notes" rows="2"></textarea>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-truck me-2"></i>Record Delivery
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Add Item Modal -->
    <div class="modal fade" id="addItemModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Inventory Item</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add">
                        
                        <div class="mb-3">
                            <label class="form-label">Name</label>
                            <input type="text" class="form-control" name="name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Category</label>
                            <select class="form-select" name="category" required>
                                <option value="">Select Category</option>
                                <option value="fuel">Fuel</option>
                                <option value="lubricants">Lubricants</option>
                                <option value="spare_parts">Spare Parts</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Initial Quantity</label>
                                <input type="number" step="0.01" min="0" class="form-control" 
                                       name="quantity" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Unit</label>
                                <select class="form-select" name="unit" required>
                                    <option value="liters">Liters</option>
                                    <option value="kg">Kilograms</option>
                                    <option value="pieces">Pieces</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Price (UGX)</label>
                                <input type="number" step="0.01" min="0" class="form-control" 
                                       name="price" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Reorder Level</label>
                                <input type="number" step="0.01" min="0" class="form-control" 
                                       name="reorder_level" required>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Supplier (optional)</label>
                            <input type="text" class="form-control" name="supplier" list="supplier-list" placeholder="Select or type a new supplier">
                            <datalist id="supplier-list">
                                {% for supplier in suppliers %}
                                <option value="{{ supplier.name }}">
                                {% endfor %}
                            </datalist>
                            <small class="text-muted">New suppliers will be automatically added to the system</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Item</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Add Supplier Modal -->
    <div class="modal fade" id="addSupplierModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Supplier</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="addSupplierForm">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Supplier Name</label>
                            <input type="text" class="form-control" id="newSupplierName" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Supplier</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Add supplier directly from the modal
        document.getElementById('addSupplierForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const supplierName = document.getElementById('newSupplierName').value.trim();
            if (!supplierName) return;
            
            // Use fetch API to add the supplier
            fetch('/add_supplier', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: supplierName
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Add the new supplier to the dropdown
                    const select = document.getElementById('supplierSelect');
                    const option = document.createElement('option');
                    option.value = data.supplier_id;
                    option.textContent = supplierName;
                    select.appendChild(option);
                    
                    // Select the newly added supplier
                    select.value = data.supplier_id;
                    
                    // Close the modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addSupplierModal'));
                    modal.hide();
                    
                    // Clear the input
                    document.getElementById('newSupplierName').value = '';
                    
                    // Show success message
                    alert('Supplier added successfully!');
                } else {
                    alert(data.error || 'Error adding supplier');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error adding supplier');
            });
        });
    </script>
</body>
</html>
""", app_name=APP_NAME, items=items, low_stock=low_stock, suppliers=suppliers, user_role=session.get("user_role"))

# ------------------- Sales Management -------------------
@app.route("/sales")
@login_required
@role_required(["admin", "manager", "attendant"])
def sales():
    branch_id = session.get("branch_id")
    
    # Get sales data with filters
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    category = request.args.get("category", "")
    payment_method = request.args.get("payment_method", "")
    
    # Base query
    query = """
        SELECT s.*, i.name as product_name, i.category as product_category, 
               u.username as employee_name, c.name as customer_name, c.vehicle_reg as customer_vehicle
        FROM sales s
        JOIN inventory i ON s.product_id = i.id
        LEFT JOIN users u ON s.employee_id = u.id
        LEFT JOIN customers c ON s.customer_id = c.id
        WHERE s.branch_id = ?
    """
    params = [branch_id]
    
    # Apply filters
    if date_from:
        query += " AND date(s.sale_date) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(s.sale_date) <= ?"
        params.append(date_to)
    if category:
        query += " AND i.category = ?"
        params.append(category)
    if payment_method:
        query += " AND s.payment_method = ?"
        params.append(payment_method)
    
    query += " ORDER BY s.sale_date DESC LIMIT 100"
    
    sales_data = query_db(query, params)
    
    # Get summary stats
    summary = query_db("""
        SELECT 
            COUNT(*) as total_sales,
            SUM(total_price) as total_revenue,
            SUM(CASE WHEN payment_method = 'cash' THEN total_price ELSE 0 END) as cash_sales,
            SUM(CASE WHEN payment_method = 'mobile_money' THEN total_price ELSE 0 END) as mobile_sales,
            SUM(CASE WHEN payment_method = 'credit' THEN total_price ELSE 0 END) as credit_sales
        FROM sales
        WHERE branch_id = ?
    """, (branch_id,), one=True)
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sales - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .summary-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .filter-section {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .badge-cash {
            background-color: #28a745;
            color: white;
        }
        .badge-mobile {
            background-color: #17a2b8;
            color: white;
        }
        .badge-credit {
            background-color: #6c757d;
            color: white;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link active">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Sales Records</h2>
                <a href="{{ url_for('quick_sale') }}" class="btn btn-primary">
                    <i class="fas fa-plus me-2"></i>New Sale
                </a>
            </div>
            
            <!-- Summary Cards -->
            <div class="row mb-4">
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-primary h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-primary text-uppercase mb-1">
                                        Total Sales
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        {{ summary.total_sales or 0 }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-shopping-cart text-primary"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-success h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-success text-uppercase mb-1">
                                        Total Revenue
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(summary.total_revenue or 0) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-dollar-sign text-success"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-info h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-info text-uppercase mb-1">
                                        Cash Sales
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(summary.cash_sales or 0) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-money-bill-wave text-info"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-warning h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-warning text-uppercase mb-1">
                                        Credit Sales
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(summary.credit_sales or 0) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-credit-card text-warning"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Filters -->
            <div class="filter-section">
                <form method="get" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" class="form-control" name="date_from" value="{{ date_from }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" class="form-control" name="date_to" value="{{ date_to }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Category</label>
                        <select class="form-select" name="category">
                            <option value="">All Categories</option>
                            <option value="fuel" {% if category == 'fuel' %}selected{% endif %}>Fuel</option>
                            <option value="lubricants" {% if category == 'lubricants' %}selected{% endif %}>Lubricants</option>
                            <option value="spare_parts" {% if category == 'spare_parts' %}selected{% endif %}>Spare Parts</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Payment Method</label>
                        <select class="form-select" name="payment_method">
                            <option value="">All Methods</option>
                            <option value="cash" {% if payment_method == 'cash' %}selected{% endif %}>Cash</option>
                            <option value="mobile_money" {% if payment_method == 'mobile_money' %}selected{% endif %}>Mobile Money</option>
                            <option value="credit" {% if payment_method == 'credit' %}selected{% endif %}>Credit</option>
                        </select>
                    </div>
                    <div class="col-md-12">
                        <button type="submit" class="btn btn-primary me-2">
                            <i class="fas fa-filter me-2"></i>Apply Filters
                        </button>
                        <a href="{{ url_for('sales') }}" class="btn btn-outline-secondary">
                            <i class="fas fa-times me-2"></i>Clear Filters
                        </a>
                    </div>
                </form>
            </div>
            
            <!-- Sales Table -->
            <div class="card">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Recent Sales (Last 100)</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Date</th>
                                    <th>Receipt No.</th>
                                    <th>Product</th>
                                    <th>Category</th>
                                    <th>Qty</th>
                                    <th>Price</th>
                                    <th>Total</th>
                                    <th>Payment</th>
                                    <th>Customer</th>
                                    <th>Vehicle</th>
                                    <th>Employee</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for sale in sales_data %}
                                <tr>
                                    <td>{{ (sale.sale_date|datetimeformat) if sale.sale_date else '-' }}</td>
                                    <td>{{ sale.receipt_number or '-' }}</td>
                                    <td>{{ sale.product_name or '-' }}</td>
                                    <td>{{ (sale.product_category|title) if sale.product_category else '-' }}</td>
                                    <td>{{ ("%.2f"|format(sale.quantity)) if sale.quantity else '0.00' }}</td>
                                    <td>UGX {{ ("{:,.0f}".format(sale.unit_price)) if sale.unit_price else '0' }}</td>
                                    <td>UGX {{ ("{:,.0f}".format(sale.total_price)) if sale.total_price else '0' }}</td>
                                    <td>
                                        {% if sale.payment_method %}
                                        <span class="badge {% if sale.payment_method == 'cash' %}badge-cash{% elif sale.payment_method == 'mobile_money' %}badge-mobile{% else %}badge-credit{% endif %}">
                                            {{ sale.payment_method|replace('_', ' ')|title }}
                                        </span>
                                        {% else %}
                                        <span class="badge badge-secondary">Unknown</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ sale.customer_name or 'Walk-in' }}</td>
                                    <td>{{ sale.customer_vehicle or '-' }}</td>
                                    <td>{{ sale.employee_name or '-' }}</td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="10" class="text-center">No sales records found</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, sales_data=sales_data, summary=summary, 
   date_from=date_from, date_to=date_to, category=category, payment_method=payment_method, user_role=session.get("user_role"))

# ------------------- Pumps Management -------------------
@app.route("/pumps", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager"])
def pumps():
    branch_id = session.get("branch_id")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            # Add new pump
            try:
                pump_number = int(request.form.get("pump_number"))
                calibration_date = request.form.get("calibration_date")
                calibration_due = request.form.get("calibration_due")
                maintenance_log = request.form.get("maintenance_log", "").strip()
                
                # Get product_id from form
                product_id = request.form.get("product_id")
                if product_id:
                    product_id = int(product_id)
                else:
                    product_id = None  # Allow None for product_id
                
                try:
                    query_db("""
                        INSERT INTO pumps 
                        (pump_number, branch_id, product_id, calibration_date, calibration_due, maintenance_log)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        pump_number, branch_id, product_id, calibration_date, calibration_due, maintenance_log
                    ), commit=True)
                except Exception as insert_error:
                    # Fallback to insert without product_id if column doesn't exist
                    query_db("""
                        INSERT INTO pumps 
                        (pump_number, branch_id, calibration_date, calibration_due, maintenance_log)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        pump_number, branch_id, calibration_date, calibration_due, maintenance_log
                    ), commit=True)
                
                flash("Pump added successfully", "success")
                
            except Exception as e:
                flash(f"Error adding pump: {str(e)}", "danger")
                
        elif action == "update":
            # Update pump
            try:
                pump_id = int(request.form.get("pump_id"))
                pump_number = int(request.form.get("pump_number"))
                calibration_date = request.form.get("calibration_date")
                calibration_due = request.form.get("calibration_due")
                maintenance_log = request.form.get("maintenance_log", "").strip()
                status = request.form.get("status")
                
                # Get product_id from form
                product_id = request.form.get("product_id")
                if product_id:
                    product_id = int(product_id)
                else:
                    product_id = None  # Allow None for product_id
                
                try:
                    query_db("""
                        UPDATE pumps SET 
                            pump_number = ?,
                            product_id = ?,
                            calibration_date = ?,
                            calibration_due = ?,
                            maintenance_log = ?,
                            status = ?
                        WHERE id = ? AND branch_id = ?
                    """, (
                        pump_number, product_id, calibration_date, calibration_due, 
                        maintenance_log, status, pump_id, branch_id
                    ), commit=True)
                except Exception as update_error:
                    # Fallback to update without product_id if column doesn't exist
                    query_db("""
                        UPDATE pumps SET 
                            pump_number = ?,
                            calibration_date = ?,
                            calibration_due = ?,
                            maintenance_log = ?,
                            status = ?
                        WHERE id = ? AND branch_id = ?
                    """, (
                        pump_number, calibration_date, calibration_due, 
                        maintenance_log, status, pump_id, branch_id
                    ), commit=True)
                
                flash("Pump updated successfully", "success")
                
            except Exception as e:
                flash(f"Error updating pump: {str(e)}", "danger")
                
        elif action == "maintenance":
            # Record maintenance
            try:
                pump_id = int(request.form.get("pump_id"))
                maintenance_type = request.form.get("maintenance_type")
                description = request.form.get("description", "").strip()
                cost = float(request.form.get("cost", 0))
                performed_by = request.form.get("performed_by", "").strip()
                
                # Get current maintenance log
                pump = query_db("SELECT maintenance_log FROM pumps WHERE id = ?", (pump_id,), one=True)
                current_log = pump["maintenance_log"] or ""
                
                # Add new maintenance record
                new_entry = f"""
                {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} - {maintenance_type}
                Performed by: {performed_by}
                Cost: UGX {cost:,.0f}
                Details: {description}
                --------------------------
                """
                
                updated_log = new_entry + current_log
                
                # Update pump record
                query_db("""
                    UPDATE pumps SET 
                        maintenance_log = ?,
                        last_maintenance = date('now'),
                        next_maintenance = date('now', '+3 months')
                    WHERE id = ? AND branch_id = ?
                """, (updated_log, pump_id, branch_id), commit=True)
                
                # Record expense
                query_db("""
                    INSERT INTO expenses 
                    (branch_id, category, amount, description, expense_date, recorded_by)
                    VALUES (?, 'pump_maintenance', ?, ?, date('now'), ?)
                """, (branch_id, cost, f"Pump maintenance: {maintenance_type}", session["user_id"]), commit=True)
                
                flash("Maintenance recorded successfully", "success")
                
            except Exception as e:
                flash(f"Error recording maintenance: {str(e)}", "danger")
                
        return redirect(url_for("pumps"))
    
    # Get all pumps for this branch
    try:
        pumps_list = query_db("""
            SELECT p.*, i.name as product_name 
            FROM pumps p
            LEFT JOIN inventory i ON p.product_id = i.id
            WHERE p.branch_id = ?
            ORDER BY p.pump_number
        """, (branch_id,))
    except Exception as e:
        # Fallback query if product_id column doesn't exist yet
        pumps_list = query_db("""
            SELECT p.*, NULL as product_name 
            FROM pumps p
            WHERE p.branch_id = ?
            ORDER BY p.pump_number
        """, (branch_id,))
    
    # Get fuel inventory items for product selection
    inventory = query_db("""
        SELECT id, name, category FROM inventory 
        WHERE branch_id = ?
        ORDER BY name
    """, (branch_id,))
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Pumps - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .pump-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .pump-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .pump-status-active {
            border-left: 4px solid #28a745;
        }
        .pump-status-inactive {
            border-left: 4px solid #6c757d;
        }
        .pump-status-maintenance {
            border-left: 4px solid #ffc107;
        }
        .maintenance-log {
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link active">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Pump Management</h2>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addPumpModal">
                    <i class="fas fa-plus me-2"></i>Add Pump
                </button>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="row">
                {% for pump in pumps_list %}
                <div class="col-md-6 mb-4">
                    <div class="pump-card card h-100 {% if pump.status == 'active' %}pump-status-active{% elif pump.status == 'inactive' %}pump-status-inactive{% else %}pump-status-maintenance{% endif %}">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <h4 class="card-title mb-1">Pump #{{ pump.pump_number }}</h4>
                                    <span class="badge {% if pump.status == 'active' %}bg-success{% elif pump.status == 'inactive' %}bg-secondary{% else %}bg-warning{% endif %}">
                                        {{ pump.status|title }}
                                    </span>
                                </div>
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
                                            type="button" data-bs-toggle="dropdown">
                                        Actions
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <button class="dropdown-item" data-bs-toggle="modal" 
                                                    data-bs-target="#editPumpModal{{ pump.id }}">
                                                <i class="fas fa-edit me-2"></i>Edit
                                            </button>
                                        </li>
                                        <li>
                                            <button class="dropdown-item" data-bs-toggle="modal" 
                                                    data-bs-target="#maintenanceModal{{ pump.id }}">
                                                <i class="fas fa-tools me-2"></i>Record Maintenance
                                            </button>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <small class="text-muted">Last Calibration:</small>
                                        <p class="mb-0">{{ pump.calibration_date or 'Not recorded' }}</p>
                                    </div>
                                    <div class="mb-3">
                                        <small class="text-muted">Next Calibration Due:</small>
                                        <p class="mb-0">{{ pump.calibration_due or 'Not set' }}</p>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <small class="text-muted">Last Maintenance:</small>
                                        <p class="mb-0">{{ pump.last_maintenance or 'Not recorded' }}</p>
                                    </div>
                                    <div class="mb-3">
                                        <small class="text-muted">Next Maintenance:</small>
                                        <p class="mb-0">{{ pump.next_maintenance or 'Not set' }}</p>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mt-3">
                                <small class="text-muted">Maintenance Log:</small>
                                <div class="maintenance-log small">
                                    {{ pump.maintenance_log or 'No maintenance records' }}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Edit Pump Modal -->
                <div class="modal fade" id="editPumpModal{{ pump.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Edit Pump #{{ pump.pump_number }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="post">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="update">
                                    <input type="hidden" name="pump_id" value="{{ pump.id }}">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Pump Number</label>
                                        <input type="number" class="form-control" name="pump_number" 
                                               value="{{ pump.pump_number }}" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Fuel Type</label>
                                        <select class="form-select" name="product_id">
                                            <option value="">-- Select Fuel Type --</option>
                                            {% for item in inventory %}
                                                {% if item.category == 'fuel' %}
                                                    <option value="{{ item.id }}" {% if pump.product_id == item.id %}selected{% endif %}>
                                                        {{ item.name }}
                                                    </option>
                                                {% endif %}
                                            {% endfor %}
                                        </select>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Calibration Date</label>
                                            <input type="date" class="form-control" name="calibration_date" 
                                                   value="{{ pump.calibration_date or '' }}">
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Next Calibration Due</label>
                                            <input type="date" class="form-control" name="calibration_due" 
                                                   value="{{ pump.calibration_due or '' }}">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Status</label>
                                        <select class="form-select" name="status" required>
                                            <option value="active" {% if pump.status == 'active' %}selected{% endif %}>Active</option>
                                            <option value="inactive" {% if pump.status == 'inactive' %}selected{% endif %}>Inactive</option>
                                            <option value="maintenance" {% if pump.status == 'maintenance' %}selected{% endif %}>Under Maintenance</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Maintenance Log</label>
                                        <textarea class="form-control" name="maintenance_log" rows="4">{{ pump.maintenance_log or '' }}</textarea>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Maintenance Modal -->
                <div class="modal fade" id="maintenanceModal{{ pump.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Record Maintenance for Pump #{{ pump.pump_number }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="post">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="maintenance">
                                    <input type="hidden" name="pump_id" value="{{ pump.id }}">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Maintenance Type</label>
                                        <select class="form-select" name="maintenance_type" required>
                                            <option value="">Select Type</option>
                                            <option value="Routine Check">Routine Check</option>
                                            <option value="Calibration">Calibration</option>
                                            <option value="Part Replacement">Part Replacement</option>
                                            <option value="Major Repair">Major Repair</option>
                                            <option value="Other">Other</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Description</label>
                                        <textarea class="form-control" name="description" rows="3" required></textarea>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Cost (UGX)</label>
                                            <input type="number" step="0.01" min="0" class="form-control" 
                                                   name="cost" required>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Performed By</label>
                                            <input type="text" class="form-control" name="performed_by" required>
                                        </div>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Record Maintenance</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                {% else %}
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i> No pumps registered for this branch
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <!-- Add Pump Modal -->
    <div class="modal fade" id="addPumpModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Pump</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add">
                        
                        <div class="mb-3">
                            <label class="form-label">Pump Number</label>
                            <input type="number" class="form-control" name="pump_number" required>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Calibration Date</label>
                                <input type="date" class="form-control" name="calibration_date">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Next Calibration Due</label>
                                <input type="date" class="form-control" name="calibration_due">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Initial Maintenance Notes</label>
                            <textarea class="form-control" name="maintenance_log" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Pump</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, pumps_list=pumps_list, user_role=session.get("user_role"), inventory=inventory)

# ------------------- Supplier Management -------------------
def sync_suppliers_from_inventory():
    """
    Synchronize suppliers from inventory to the suppliers table
    """
    try:
        # Get distinct suppliers from inventory
        inventory_suppliers = query_db(
            "SELECT DISTINCT supplier FROM inventory WHERE supplier IS NOT NULL AND supplier != ''"
        )
        
        if not inventory_suppliers:
            return 0
            
        # Get existing suppliers
        existing_suppliers = query_db("SELECT name FROM suppliers")
        existing_names = [s['name'] for s in existing_suppliers]
        
        # Find suppliers to add
        suppliers_to_add = [s['supplier'] for s in inventory_suppliers if s['supplier'] not in existing_names]
        
        # Add new suppliers
        conn = get_db()
        c = conn.cursor()
        for supplier_name in suppliers_to_add:
            c.execute("INSERT INTO suppliers (name) VALUES (?)", (supplier_name,))
        
        conn.commit()
        conn.close()
        
        return len(suppliers_to_add)
    except Exception as e:
        print(f"Error syncing suppliers: {str(e)}")
        return 0

@app.route('/add_supplier', methods=['POST'])
@login_required
@role_required(["admin", "manager"])
def add_supplier():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        
        if not name:
            return jsonify({'success': False, 'error': 'Supplier name is required'})
        
        # Check if supplier already exists
        existing = query_db("SELECT id FROM suppliers WHERE name = ?", (name,), one=True)
        if existing:
            return jsonify({'success': True, 'supplier_id': existing['id'], 'message': 'Supplier already exists'})
        
        # Add new supplier
        cur = get_db().cursor()
        cur.execute("INSERT INTO suppliers (name) VALUES (?)", (name,))
        get_db().commit()
        supplier_id = cur.lastrowid
        
        # Log the action
        add_audit_log(
            session["user_id"],
            "Add Supplier",
            f"Added supplier: {name}",
            request.remote_addr,
            request.user_agent.string,
            session.get("branch_id")
        )
        
        return jsonify({'success': True, 'supplier_id': supplier_id, 'message': 'Supplier added successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ------------------- Customers Management -------------------
@app.route("/customers", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager", "attendant"])
def customers():
    branch_id = session.get("branch_id")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            # Add new customer
            try:
                name = request.form.get("name").strip()
                phone = request.form.get("phone", "").strip()
                email = request.form.get("email", "").strip()
                address = request.form.get("address", "").strip()
                vehicle_reg = request.form.get("vehicle_reg", "").strip()
                customer_type = request.form.get("customer_type", "retail")
                credit_limit = float(request.form.get("credit_limit", 0))
                tax_id = request.form.get("tax_id", "").strip()
                
                query_db("""
                    INSERT INTO customers 
                    (name, phone, email, address, vehicle_reg, customer_type, branch_id, credit_limit, tax_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    name, phone, email, address, vehicle_reg, customer_type, branch_id, credit_limit, tax_id
                ), commit=True)
                
                flash("Customer added successfully", "success")
                
            except Exception as e:
                flash(f"Error adding customer: {str(e)}", "danger")
                
        elif action == "update":
            # Update customer
            try:
                customer_id = int(request.form.get("customer_id"))
                name = request.form.get("name").strip()
                phone = request.form.get("phone", "").strip()
                email = request.form.get("email", "").strip()
                address = request.form.get("address", "").strip()
                vehicle_reg = request.form.get("vehicle_reg", "").strip()
                customer_type = request.form.get("customer_type", "retail")
                credit_limit = float(request.form.get("credit_limit", 0))
                tax_id = request.form.get("tax_id", "").strip()
                
                query_db("""
                    UPDATE customers SET 
                        name = ?,
                        phone = ?,
                        email = ?,
                        address = ?,
                        vehicle_reg = ?,
                        customer_type = ?,
                        credit_limit = ?,
                        tax_id = ?
                    WHERE id = ? AND branch_id = ?
                """, (
                    name, phone, email, address, vehicle_reg, customer_type, credit_limit, tax_id, customer_id, branch_id
                ), commit=True)
                
                flash("Customer updated successfully", "success")
                
            except Exception as e:
                flash(f"Error updating customer: {str(e)}", "danger")
                
        elif action == "payment":
            # Record customer payment
            try:
                customer_id = int(request.form.get("customer_id"))
                amount = float(request.form.get("amount", 0))
                payment_method = request.form.get("payment_method", "cash")
                reference = request.form.get("reference", "").strip()
                notes = request.form.get("notes", "").strip()
                
                # Get current balance
                customer = query_db(
                    "SELECT outstanding_balance FROM customers WHERE id = ? AND branch_id = ?", 
                    (customer_id, branch_id), one=True
                )
                
                if not customer:
                    flash("Customer not found", "danger")
                    return redirect(url_for("customers"))
                
                current_balance = customer["outstanding_balance"]
                new_balance = current_balance - amount
                
                if new_balance < 0:
                    flash("Payment amount exceeds outstanding balance", "warning")
                    return redirect(url_for("customers"))
                
                # Update customer balance
                query_db(
                    "UPDATE customers SET outstanding_balance = ? WHERE id = ? AND branch_id = ?", 
                    (new_balance, customer_id, branch_id), commit=True
                )
                
                # Record transaction
                query_db(
                    "INSERT INTO customer_transactions (customer_id, transaction_type, amount, balance, reference, notes, employee_id) VALUES (?, 'payment', ?, ?, ?, ?, ?)", 
                    (customer_id, amount, new_balance, reference, notes, session["user_id"]), commit=True
                )
                
                flash("Payment recorded successfully", "success")
                
            except Exception as e:
                flash(f"Error recording payment: {str(e)}", "danger")
                
        return redirect(url_for("customers"))
    
    # Get all customers for this branch
    customers_list = query_db("""
        SELECT * FROM customers 
        WHERE branch_id = ?
        ORDER BY name
    """, (branch_id,))
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Customers - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .customer-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .customer-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .customer-retail {
            border-left: 4px solid #17a2b8;
        }
        .customer-wholesale {
            border-left: 4px solid #28a745;
        }
        .customer-corporate {
            border-left: 4px solid #6f42c1;
        }
        .balance-positive {
            color: #dc3545;
            font-weight: bold;
        }
        .balance-zero {
            color: #6c757d;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link active">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Customer Management</h2>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addCustomerModal">
                    <i class="fas fa-plus me-2"></i>Add Customer
                </button>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="row">
                {% for customer in customers_list %}
                <div class="col-md-6 mb-4">
                    <div class="customer-card card h-100 {% if customer.customer_type == 'retail' %}customer-retail{% elif customer.customer_type == 'wholesale' %}customer-wholesale{% else %}customer-corporate{% endif %}">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <h4 class="card-title mb-1">{{ customer.name }}</h4>
                                    <span class="badge {% if customer.customer_type == 'retail' %}bg-info{% elif customer.customer_type == 'wholesale' %}bg-success{% else %}bg-primary{% endif %}">
                                        {{ customer.customer_type|title }}
                                    </span>
                                </div>
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
                                            type="button" data-bs-toggle="dropdown">
                                        Actions
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <button class="dropdown-item" data-bs-toggle="modal" 
                                                    data-bs-target="#editCustomerModal{{ customer.id }}">
                                                <i class="fas fa-edit me-2"></i>Edit
                                            </button>
                                        </li>
                                        <li>
                                            <button class="dropdown-item" data-bs-toggle="modal" 
                                                    data-bs-target="#paymentModal{{ customer.id }}">
                                                <i class="fas fa-money-bill-wave me-2"></i>Record Payment
                                            </button>
                                        </li>
                                        <li>
                                            <a class="dropdown-item" href="{{ url_for('customer_details', id=customer.id) }}">
                                                <i class="fas fa-eye me-2"></i>View Details
                                            </a>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <small class="text-muted">Phone:</small>
                                        <p class="mb-0">{{ customer.phone or '-' }}</p>
                                    </div>
                                    <div class="mb-3">
                                        <small class="text-muted">Email:</small>
                                        <p class="mb-0">{{ customer.email or '-' }}</p>
                                    </div>
                                    {% if customer.vehicle_reg %}
                                    <div class="mb-3">
                                        <small class="text-muted">Vehicle Registration:</small>
                                        <p class="mb-0"><strong>{{ customer.vehicle_reg }}</strong></p>
                                    </div>
                                    {% endif %}
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <small class="text-muted">Credit Limit:</small>
                                        <p class="mb-0">UGX {{ "{:,.0f}".format(customer.credit_limit) }}</p>
                                    </div>
                                    <div class="mb-3">
                                        <small class="text-muted">Outstanding Balance:</small>
                                        <p class="mb-0 {% if customer.outstanding_balance > 0 %}balance-positive{% else %}balance-zero{% endif %}">
                                            UGX {{ "{:,.0f}".format(customer.outstanding_balance) }}
                                        </p>
                                    </div>
                                </div>
                            </div>
                            
                            {% if customer.address %}
                            <div class="mt-3">
                                <small class="text-muted">Address:</small>
                                <p class="mb-0 small">{{ customer.address }}</p>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                <!-- Edit Customer Modal -->
                <div class="modal fade" id="editCustomerModal{{ customer.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Edit {{ customer.name }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="post">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="update">
                                    <input type="hidden" name="customer_id" value="{{ customer.id }}">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Name</label>
                                        <input type="text" class="form-control" name="name" 
                                               value="{{ customer.name }}" required>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Phone</label>
                                            <input type="text" class="form-control" name="phone" 
                                                   value="{{ customer.phone or '' }}">
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Email</label>
                                            <input type="email" class="form-control" name="email" 
                                                   value="{{ customer.email or '' }}">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Address</label>
                                        <textarea class="form-control" name="address" rows="2">{{ customer.address or '' }}</textarea>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Vehicle Registration</label>
                                        <input type="text" class="form-control" name="vehicle_reg" 
                                               value="{{ customer.vehicle_reg or '' }}"
                                               placeholder="Enter vehicle registration number">
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Customer Type</label>
                                            <select class="form-select" name="customer_type" required>
                                                <option value="retail" {% if customer.customer_type == 'retail' %}selected{% endif %}>Retail</option>
                                                <option value="wholesale" {% if customer.customer_type == 'wholesale' %}selected{% endif %}>Wholesale</option>
                                                <option value="corporate" {% if customer.customer_type == 'corporate' %}selected{% endif %}>Corporate</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Credit Limit (UGX)</label>
                                            <input type="number" step="0.01" min="0" class="form-control" 
                                                   name="credit_limit" value="{{ customer.credit_limit }}">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Tax ID (optional)</label>
                                        <input type="text" class="form-control" name="tax_id" 
                                               value="{{ customer.tax_id or '' }}">
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Payment Modal -->
                <div class="modal fade" id="paymentModal{{ customer.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Record Payment for {{ customer.name }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="post">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="payment">
                                    <input type="hidden" name="customer_id" value="{{ customer.id }}">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Current Balance</label>
                                        <input type="text" class="form-control bg-light" 
                                               value="UGX {{ "{:,.0f}".format(customer.outstanding_balance) }}" readonly>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Payment Amount (UGX)</label>
                                        <input type="number" step="0.01" min="0.01" 
                                               max="{{ customer.outstanding_balance }}" 
                                               class="form-control" name="amount" required>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Payment Method</label>
                                            <select class="form-select" name="payment_method" required>
                                                <option value="cash">Cash</option>
                                                <option value="mobile_money">Mobile Money</option>
                                                <option value="bank_transfer">Bank Transfer</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Reference (optional)</label>
                                            <input type="text" class="form-control" name="reference">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Notes (optional)</label>
                                        <textarea class="form-control" name="notes" rows="2"></textarea>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Record Payment</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                {% else %}
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i> No customers registered for this branch
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <!-- Add Customer Modal -->
    <div class="modal fade" id="addCustomerModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Customer</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add">
                        
                        <div class="mb-3">
                            <label class="form-label">Name</label>
                            <input type="text" class="form-control" name="name" required>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Phone</label>
                                <input type="text" class="form-control" name="phone">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Email</label>
                                <input type="email" class="form-control" name="email">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Address</label>
                            <textarea class="form-control" name="address" rows="2"></textarea>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Vehicle Registration</label>
                            <input type="text" class="form-control" name="vehicle_reg" 
                                   placeholder="Enter vehicle registration number">
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Customer Type</label>
                                <select class="form-select" name="customer_type" required>
                                    <option value="retail">Retail</option>
                                    <option value="wholesale">Wholesale</option>
                                    <option value="corporate">Corporate</option>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Credit Limit (UGX)</label>
                                <input type="number" step="0.01" min="0" class="form-control" 
                                       name="credit_limit" value="0">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Tax ID (optional)</label>
                            <input type="text" class="form-control" name="tax_id">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Customer</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, customers_list=customers_list, user_role=session.get("user_role"))

# ------------------- Branch Switching -------------------
@app.route('/switch_branch/<int:branch_id>')
@login_required
@role_required(["admin", "manager"])
def switch_branch(branch_id):
    # Get branch info
    branch = query_db("SELECT * FROM branches WHERE id = ?", (branch_id,), one=True)
    
    if not branch:
        flash("Branch not found", "danger")
        return redirect(url_for('dashboard'))
    
    # Update session with new branch
    session["branch_id"] = branch["id"]
    session["branch_name"] = branch["name"]
    
    # Log branch switch
    user_id = session.get("user_id")
    add_audit_log(
        user_id,
        f"Switched to branch: {branch['name']}",
        "branch_management"
    )
    
    flash(f"Switched to {branch['name']} branch", "success")
    return redirect(request.referrer or url_for('dashboard'))

# ------------------- Branch Management -------------------
@app.route('/branch_management', methods=["GET", "POST"])
@login_required
@role_required(["admin"])
def branch_management():
    user_id = session.get("user_id")
    branch_id = session.get("branch_id")
    
    # Handle adding/editing branch
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        location = request.form.get("location", "").strip()
        contact = request.form.get("contact", "").strip()
        edit_branch_id = request.form.get("branch_id")
        
        # Validate inputs
        if not name:
            flash("Branch name is required", "danger")
        else:
            conn = get_db()
            c = conn.cursor()
            
            # Update existing branch
            if edit_branch_id:
                c.execute(
                    "UPDATE branches SET name = ?, location = ?, contact = ? WHERE id = ?",
                    (name, location, contact, edit_branch_id)
                )
                flash("Branch updated successfully", "success")
            # Add new branch
            else:
                c.execute(
                    "INSERT INTO branches (name, location, contact) VALUES (?, ?, ?)",
                    (name, location, contact)
                )
                flash("New branch added successfully", "success")
            
            conn.commit()
            
            # Log action
            add_audit_log(
                user_id,
                f"{'Updated' if edit_branch_id else 'Added'} branch: {name}",
                "branch_management"
            )
            
            return redirect(url_for('branch_management'))
    
    # Get all branches for display
    branch_rows = query_db("SELECT * FROM branches ORDER BY name")
    branches = []
    
    # Convert Row objects to dictionaries and get metrics
    for branch_row in branch_rows:
        # Convert to dictionary
        branch = dict(branch_row)
        
        # Initialize empty metrics structure
        branch['metrics'] = {
            'sales': {'total_sales': 0, 'transaction_count': 0, 'today_sales': 0, 'monthly_sales': 0},
            'inventory': {'item_count': 0, 'inventory_value': 0, 'low_stock_count': 0},
            'employee_count': 0
        }
        
        # Get branch metrics using the utility function
        branch_info = get_branch_info(branch['id'])
        if branch_info and 'metrics' in branch_info:
            branch['metrics'] = branch_info['metrics']
            
        branches.append(branch)
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Branch Management - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .branch-card {
            transition: all 0.3s;
            border-radius: 10px;
        }
        .branch-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .current-branch {
            border-left: 4px solid var(--primary);
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if session.get('user_role') in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% if session.get('user_role') == 'admin' %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('branch_management') }}" class="sidebar-nav-link active">
                    <i class="fas fa-building"></i> Branches
                </a>
            </li>
            {% endif %}
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" data-bs-toggle="dropdown">
                            <div class="user-avatar me-2">
                                {{ session.get('username', 'U')[0].upper() }}
                            </div>
                            <span>{{ session.get('username', 'User') }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user-circle me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>
        
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Branch Management</h2>
            <div>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addBranchModal">
                    <i class="fas fa-plus-circle me-2"></i>Add New Branch
                </button>
            </div>
        </div>
        
        <!-- Branch Cards -->
        <div class="row">
            {% for branch in branches %}
            <div class="col-md-6 mb-4">
                <div class="card branch-card {% if branch.id == branch_id %}current-branch{% endif %}">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            {{ branch.name }}
                            {% if branch.id == branch_id %}
                            <span class="badge bg-primary ms-2">Current</span>
                            {% endif %}
                        </h5>
                        <div class="btn-group" role="group" aria-label="Branch actions">
                            {% if branch.id != branch_id %}
                            <a href="{{ url_for('switch_branch', branch_id=branch.id) }}" class="btn btn-sm btn-outline-primary" title="Switch to this branch">
                                <i class="fas fa-exchange-alt"></i>
                            </a>
                            {% endif %}
                            <button type="button" class="btn btn-sm btn-outline-secondary" title="Edit branch"
                                    data-bs-toggle="modal" data-bs-target="#editBranchModal{{ branch.id }}">
                                <i class="fas fa-edit"></i>
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <div class="mb-2">
                                    <small class="text-muted">Location:</small>
                                    <p class="mb-0">{{ branch.location or 'Not specified' }}</p>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-2">
                                    <small class="text-muted">Contact:</small>
                                    <p class="mb-0">{{ branch.contact or 'Not specified' }}</p>
                                </div>
                            </div>
                        </div>
                        
                        <h6 class="mt-3 mb-3 border-bottom pb-2">Performance Metrics</h6>
                        <div class="row g-2">
                            <div class="col-md-4">
                                <div class="p-2 border rounded">
                                    <small class="text-muted d-block">Today's Sales</small>
                                    <span class="fw-bold">UGX {{ "{:,.0f}".format(branch.metrics.sales.today_sales) }}</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-2 border rounded">
                                    <small class="text-muted d-block">Monthly Sales</small>
                                    <span class="fw-bold">UGX {{ "{:,.0f}".format(branch.metrics.sales.monthly_sales) }}</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-2 border rounded">
                                    <small class="text-muted d-block">Total Sales</small>
                                    <span class="fw-bold">UGX {{ "{:,.0f}".format(branch.metrics.sales.total_sales) }}</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-2 border rounded">
                                    <small class="text-muted d-block">Inventory Value</small>
                                    <span class="fw-bold">UGX {{ "{:,.0f}".format(branch.metrics.inventory.inventory_value) }}</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-2 border rounded">
                                    <small class="text-muted d-block">Inventory Items</small>
                                    <span class="fw-bold">{{ branch.metrics.inventory.item_count }}</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-2 border rounded">
                                    <small class="text-muted d-block">Employees</small>
                                    <span class="fw-bold">{{ branch.metrics.employee_count }}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Edit Branch Modal -->
                <div class="modal fade" id="editBranchModal{{ branch.id }}" tabindex="-1" aria-labelledby="editBranchModalLabel{{ branch.id }}" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="editBranchModalLabel{{ branch.id }}">Edit Branch</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <form method="post" action="{{ url_for('branch_management') }}">
                                    <input type="hidden" name="branch_id" value="{{ branch.id }}">
                                    <div class="mb-3">
                                        <label for="name{{ branch.id }}" class="form-label">Branch Name</label>
                                        <input type="text" class="form-control" id="name{{ branch.id }}" name="name" value="{{ branch.name }}" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="location{{ branch.id }}" class="form-label">Location</label>
                                        <input type="text" class="form-control" id="location{{ branch.id }}" name="location" value="{{ branch.location }}">
                                    </div>
                                    <div class="mb-3">
                                        <label for="contact{{ branch.id }}" class="form-label">Contact</label>
                                        <input type="text" class="form-control" id="contact{{ branch.id }}" name="contact" value="{{ branch.contact }}">
                                    </div>
                                    <div class="text-end">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                        <button type="submit" class="btn btn-primary">Save Changes</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <!-- Add New Branch Modal -->
    <div class="modal fade" id="addBranchModal" tabindex="-1" aria-labelledby="addBranchModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addBranchModalLabel">Add New Branch</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="{{ url_for('branch_management') }}">
                        <div class="mb-3">
                            <label for="name" class="form-label">Branch Name</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label for="location" class="form-label">Location</label>
                            <input type="text" class="form-control" id="location" name="location">
                        </div>
                        <div class="mb-3">
                            <label for="contact" class="form-label">Contact</label>
                            <input type="text" class="form-control" id="contact" name="contact">
                        </div>
                        <div class="text-end">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-primary">Add Branch</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, branches=branches, branch_id=branch_id)

# ------------------- Customer Details -------------------
@app.route("/customers/<int:id>")
@login_required
@role_required(["admin", "manager", "attendant"])
def customer_details(id):
    branch_id = session.get("branch_id")
    
    # Get customer details
    customer = query_db("""
        SELECT * FROM customers 
        WHERE id = ? AND branch_id = ?
    """, (id, branch_id), one=True)
    
    if not customer:
        flash("Customer not found", "danger")
        return redirect(url_for("customers"))
    
    # Get customer transactions
    transactions = query_db("""
        SELECT * FROM customer_transactions
        WHERE customer_id = ?
        ORDER BY transaction_date DESC
        LIMIT 50
    """, (id,))
    
    # Get customer sales
    sales = query_db("""
        SELECT s.*, i.name as product_name 
        FROM sales s
        JOIN inventory i ON s.product_id = i.id
        WHERE s.customer_id = ?
        ORDER BY s.sale_date DESC
        LIMIT 20
    """, (id,))
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ customer.name }} - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .customer-header {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .transaction-sale {
            border-left: 4px solid #28a745;
        }
        .transaction-payment {
            border-left: 4px solid #17a2b8;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="customer-header">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h2>{{ customer.name }}</h2>
                        <span class="badge {% if customer.customer_type == 'retail' %}bg-info{% elif customer.customer_type == 'wholesale' %}bg-success{% else %}bg-primary{% endif %}">
                            {{ customer.customer_type|title }}
                        </span>
                    </div>
                    <div class="text-end">
                        <h4 class="{% if customer.outstanding_balance > 0 %}text-danger{% else %}text-muted{% endif %}">
                            UGX {{ "{:,.0f}".format(customer.outstanding_balance) }}
                        </h4>
                        <small>Outstanding Balance</small>
                    </div>
                </div>
                
                <hr>
                
                <div class="row">
                    <div class="col-md-4">
                        <p><i class="fas fa-phone me-2"></i> {{ customer.phone or 'Not provided' }}</p>
                    </div>
                    <div class="col-md-4">
                        <p><i class="fas fa-envelope me-2"></i> {{ customer.email or 'Not provided' }}</p>
                    </div>
                    <div class="col-md-4">
                        <p><i class="fas fa-credit-card me-2"></i> Credit Limit: UGX {{ "{:,.0f}".format(customer.credit_limit) }}</p>
                    </div>
                </div>
                
                {% if customer.address %}
                <div class="mt-2">
                    <p><i class="fas fa-map-marker-alt me-2"></i> {{ customer.address }}</p>
                </div>
                {% endif %}
                
                {% if customer.tax_id %}
                <div class="mt-2">
                    <p><i class="fas fa-id-card me-2"></i> Tax ID: {{ customer.tax_id }}</p>
                </div>
                {% endif %}
            </div>
            
            <div class="row">
                <!-- Transactions -->
                <div class="col-md-6 mb-4">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Recent Transactions</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Type</th>
                                            <th>Amount</th>
                                            <th>Balance</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for txn in transactions %}
                                        <tr class="{% if txn.transaction_type == 'sale' %}transaction-sale{% else %}transaction-payment{% endif %}">
                                            <td>{{ txn.transaction_date|datetimeformat }}</td>
                                            <td>{{ txn.transaction_type|title }}</td>
                                            <td>UGX {{ "{:,.0f}".format(txn.amount) }}</td>
                                            <td>UGX {{ "{:,.0f}".format(txn.balance) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="4" class="text-center">No transactions found</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Sales -->
                <div class="col-md-6 mb-4">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Recent Purchases</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Product</th>
                                            <th>Amount</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for sale in sales %}
                                        <tr>
                                            <td>{{ sale.sale_date|datetimeformat }}</td>
                                            <td>{{ sale.product_name }}</td>
                                            <td>UGX {{ "{:,.0f}".format(sale.total_price) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="3" class="text-center">No purchases found</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, customer=customer, transactions=transactions, sales=sales, user_role=session.get("user_role"))

# ------------------- Employees Management -------------------
@app.route("/employees", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager"])
def employees():
    branch_id = session.get("branch_id")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            # Add new employee
            try:
                username = request.form.get("username").strip()
                password = request.form.get("password")
                confirm_password = request.form.get("confirm_password")
                full_name = request.form.get("full_name").strip()
                role = request.form.get("role")
                emp_branch_id = request.form.get("branch_id")
                phone = request.form.get("phone", "").strip()
                email = request.form.get("email", "").strip()
                
                # Validate inputs
                if not username or not password or not full_name or not role:
                    flash("All required fields must be filled", "danger")
                    return redirect(url_for("employees"))
                    
                if password != confirm_password:
                    flash("Passwords do not match", "danger")
                    return redirect(url_for("employees"))
                
                if not emp_branch_id:
                    flash("Branch assignment is required", "danger")
                    return redirect(url_for("employees"))
                    
                # Check if username already exists
                existing_user = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
                if existing_user:
                    flash(f"Username '{username}' already exists", "danger")
                    return redirect(url_for("employees"))
                
                # Create the user
                if not create_user(username, password, role, emp_branch_id, full_name, phone, email):
                    flash("Error creating user", "danger")
                    return redirect(url_for("employees"))
                
                # Log the action
                add_audit_log(
                    session["user_id"],
                    "Add Employee",
                    f"Added user: {username}, Role: {role}, Branch: {emp_branch_id}",
                    request.remote_addr,
                    request.user_agent.string,
                    branch_id
                )
                
                flash(f"Employee '{full_name}' ({username}) added successfully", "success")
                
            except Exception as e:
                flash(f"Error adding employee: {str(e)}", "danger")
                
        elif action == "update":
            # Update employee
            try:
                user_id = int(request.form.get("user_id"))
                username = request.form.get("username").strip()
                full_name = request.form.get("full_name").strip()
                role = request.form.get("role")
                emp_branch_id = request.form.get("branch_id")
                phone = request.form.get("phone", "").strip()
                email = request.form.get("email", "").strip()
                
                # Validate inputs
                if not username or not full_name or not role:
                    flash("All required fields must be filled", "danger")
                    return redirect(url_for("employees"))
                
                if not emp_branch_id:
                    flash("Branch assignment is required", "danger")
                    return redirect(url_for("employees"))
                
                # Check if username already exists and belongs to a different user
                existing_user = query_db(
                    "SELECT id FROM users WHERE username = ? AND id != ?", 
                    (username, user_id), one=True
                )
                if existing_user:
                    flash(f"Username '{username}' already exists", "danger")
                    return redirect(url_for("employees"))
                
                # Get the current user details for logging
                current_user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
                
                # Special check for users modifying their own accounts
                if user_id == session.get("user_id"):
                    if role != "admin" and session.get("user_role") == "admin":
                        flash("Warning: You cannot downgrade your own admin role", "warning")
                        return redirect(url_for("employees"))
                
                # Update the user
                if not update_user(user_id, username, role, emp_branch_id, full_name, phone, email):
                    flash("Error updating employee. If you're trying to change your own role from admin, this is not allowed to prevent access loss.", "danger")
                    return redirect(url_for("employees"))
                
                # Log the action
                add_audit_log(
                    session["user_id"],
                    "Update Employee",
                    f"Updated user: {username} (ID: {user_id}), New role: {role}, New branch: {emp_branch_id}",
                    request.remote_addr,
                    request.user_agent.string,
                    branch_id
                )
                
                flash(f"Employee '{full_name}' updated successfully", "success")
                
            except Exception as e:
                flash(f"Error updating employee: {str(e)}", "danger")
                
        elif action == "password":
            # Change password
            try:
                user_id = int(request.form.get("user_id"))
                new_password = request.form.get("new_password")
                confirm_password = request.form.get("confirm_password")
                
                # Validate inputs
                if not new_password:
                    flash("Password cannot be empty", "danger")
                    return redirect(url_for("employees"))
                
                if new_password != confirm_password:
                    flash("Passwords do not match", "danger")
                    return redirect(url_for("employees"))
                
                # Get the user details for logging
                user = query_db("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
                
                # Change the password
                if not change_password(user_id, new_password):
                    flash("Error changing password", "danger")
                    return redirect(url_for("employees"))
                
                # Log the action
                add_audit_log(
                    session["user_id"],
                    "Change Password",
                    f"Changed password for user ID: {user_id}, Username: {user['username']}",
                    request.remote_addr,
                    request.user_agent.string,
                    branch_id
                )
                
                flash(f"Password for {user['username']} changed successfully", "success")
                
            except Exception as e:
                flash(f"Error changing password: {str(e)}", "danger")
                
        return redirect(url_for("employees"))
    
    # Get all employees
    employees_list = query_db("""
        SELECT u.*, b.name as branch_name 
        FROM users u
        LEFT JOIN branches b ON u.branch_id = b.id
        ORDER BY u.role, u.username
    """)
    
    # Get all branches for admin
    branches = query_db("SELECT * FROM branches ORDER BY name")
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Employees - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <!-- Employee management custom styles -->
    <style>
        /* Role-based styling for employee cards */
        .employee-card.role-admin {
            border-left: 5px solid #dc3545;
            box-shadow: 0 2px 8px rgba(220, 53, 69, 0.1);
        }
        .employee-card.role-manager {
            border-left: 5px solid #ffc107;
            box-shadow: 0 2px 8px rgba(255, 193, 7, 0.1);
        }
        .employee-card.role-attendant {
            border-left: 5px solid #28a745;
            box-shadow: 0 2px 8px rgba(40, 167, 69, 0.1);
        }
        .employee-card {
            transition: all 0.2s ease;
        }
        .employee-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .badge {
            font-size: 0.8rem;
            margin-right: 5px;
        }
    </style>
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .employee-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .employee-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .role-admin {
            border-left: 4px solid #dc3545;
        }
        .role-manager {
            border-left: 4px solid #fd7e14;
        }
        .role-attendant {
            border-left: 4px solid #28a745;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link active">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Employee Management</h2>
            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addEmployeeModal">
                    <i class="fas fa-plus me-2"></i>Add Employee
                </button>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="row">
                {% for emp in employees_list %}
                <div class="col-md-6 mb-4">
                    <div class="employee-card card h-100 {% if emp.role == 'admin' %}role-admin{% elif emp.role == 'manager' %}role-manager{% else %}role-attendant{% endif %}">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <h4 class="card-title mb-1">{{ emp.full_name or emp.username }}</h4>
                                    <div>
                                        <span class="badge {% if emp.role == 'admin' %}bg-danger{% elif emp.role == 'manager' %}bg-warning{% else %}bg-success{% endif %}">
                                            {{ emp.role|title }}
                                        </span>
                                        {% if emp.role in ['admin', 'manager'] %}
                                        <span class="badge bg-info">
                                            <i class="fas fa-users-cog"></i> Employee Management Access
                                        </span>
                                        {% endif %}
                                    </div>
                                    <div class="small text-muted mt-1">
                                        <i class="fas fa-building"></i> {{ emp.branch_name or 'No Branch Assigned' }}
                                    </div>
                                </div>
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
                                            type="button" data-bs-toggle="dropdown">
                                        Actions
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <button class="dropdown-item" data-bs-toggle="modal" 
                                                    data-bs-target="#editEmployeeModal{{ emp.id }}">
                                                <i class="fas fa-edit me-2"></i>Edit
                                            </button>
                                        </li>
                                        <li>
                                            <button class="dropdown-item" data-bs-toggle="modal" 
                                                    data-bs-target="#passwordModal{{ emp.id }}">
                                                <i class="fas fa-key me-2"></i>Change Password
                                            </button>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <small class="text-muted">Username:</small>
                                        <p class="mb-0">{{ emp.username }}</p>
                                    </div>
                                    <div class="mb-3">
                                        <small class="text-muted">Branch:</small>
                                        <p class="mb-0">{{ emp.branch_name or 'N/A' }}</p>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <small class="text-muted">Phone:</small>
                                        <p class="mb-0">{{ emp.phone or '-' }}</p>
                                    </div>
                                    <div class="mb-3">
                                        <small class="text-muted">Email:</small>
                                        <p class="mb-0">{{ emp.email or '-' }}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Edit Employee Modal -->
                <div class="modal fade" id="editEmployeeModal{{ emp.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Edit {{ emp.full_name or emp.username }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="post">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="update">
                                    <input type="hidden" name="user_id" value="{{ emp.id }}">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Username</label>
                                        <input type="text" class="form-control" name="username" 
                                               value="{{ emp.username }}" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Full Name</label>
                                        <input type="text" class="form-control" name="full_name" 
                                               value="{{ emp.full_name or '' }}" required>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Role</label>
                                            <select class="form-select" name="role" required>
                                                <option value="admin" {% if emp.role == 'admin' %}selected{% endif %}>Admin - Full Access</option>
                                                <option value="manager" {% if emp.role == 'manager' %}selected{% endif %}>Manager - Full Access</option>
                                                <option value="attendant" {% if emp.role == 'attendant' %}selected{% endif %}>Attendant - Limited Access</option>
                                            </select>
                                            <div class="form-text">
                                                <span class="text-info"><i class="fas fa-info-circle"></i> Admin/Manager roles can access Employee Management</span>
                                            </div>
                                            {% if emp.id == session.user_id and emp.role == 'admin' %}
                                            <div class="alert alert-warning mt-2 p-1 small">
                                                <i class="fas fa-exclamation-triangle"></i> You cannot downgrade your own admin role
                                            </div>
                                            {% endif %}
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Branch Assignment <span class="text-danger">*</span></label>
                                            <select class="form-select" name="branch_id" required>
                                                <option value="">Select Branch</option>
                                                {% for branch in branches %}
                                                <option value="{{ branch.id }}" {% if emp.branch_id == branch.id %}selected{% endif %}>
                                                    {{ branch.name }}
                                                </option>
                                                {% endfor %}
                                            </select>
                                            <small class="text-muted">Users must be assigned to a branch</small>
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label class="form-label">Phone</label>
                                            <input type="text" class="form-control" name="phone" 
                                                   value="{{ emp.phone or '' }}">
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Email</label>
                                            <input type="email" class="form-control" name="email" 
                                                   value="{{ emp.email or '' }}">
                                        </div>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Password Modal -->
                <div class="modal fade" id="passwordModal{{ emp.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Change Password for {{ emp.full_name or emp.username }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="post">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="password">
                                    <input type="hidden" name="user_id" value="{{ emp.id }}">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">New Password</label>
                                        <input type="password" class="form-control" name="new_password" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Confirm New Password</label>
                                        <input type="password" class="form-control" name="confirm_password" required>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Change Password</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                {% else %}
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i> No employees registered in the system
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <!-- Add Employee Modal -->
    <div class="modal fade" id="addEmployeeModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Employee</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add">
                        
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" class="form-control" name="username" required>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Password</label>
                                <input type="password" class="form-control" name="password" id="password" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" name="confirm_password" id="confirm_password" required>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Full Name</label>
                            <input type="text" class="form-control" name="full_name" required>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Role</label>
                                <select class="form-select" name="role" id="roleSelect" required>
                                    <option value="admin">Admin - Full Access</option>
                                    <option value="manager">Manager - Full Access</option>
                                    <option value="attendant">Attendant - Limited Access</option>
                                </select>
                                <div class="form-text" id="roleHelpText">
                                    <span class="text-info"><i class="fas fa-info-circle"></i> Admin/Manager roles can access Employee Management</span>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Branch Assignment <span class="text-danger">*</span></label>
                                <select class="form-select" name="branch_id" required>
                                    <option value="">Select Branch</option>
                                    {% for branch in branches %}
                                    <option value="{{ branch.id }}">{{ branch.name }}</option>
                                    {% endfor %}
                                </select>
                                <small class="text-muted">Users must be assigned to a branch</small>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Phone</label>
                                <input type="text" class="form-control" name="phone">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Email</label>
                                <input type="email" class="form-control" name="email">
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Employee</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password confirmation validation
        document.querySelectorAll('form').forEach(form => {
            // Check for change password form
            if (form.querySelector('input[name="new_password"]')) {
                form.addEventListener('submit', function(e) {
                    const newPass = form.querySelector('input[name="new_password"]').value;
                    const confirmPass = form.querySelector('input[name="confirm_password"]').value;
                    
                    if (newPass !== confirmPass) {
                        e.preventDefault();
                        alert('Passwords do not match');
                    }
                });
            }
            
            // Check for add employee form
            if (form.querySelector('input[name="password"]') && form.querySelector('input[name="confirm_password"]')) {
                form.addEventListener('submit', function(e) {
                    const pass = form.querySelector('input[name="password"]').value;
                    const confirmPass = form.querySelector('input[name="confirm_password"]').value;
                    
                    if (pass !== confirmPass) {
                        e.preventDefault();
                        alert('Passwords do not match');
                    }
                });
            }
        });
        
        // Update role help text
        const roleSelect = document.getElementById('roleSelect');
        if (roleSelect) {
            roleSelect.addEventListener('change', function() {
                const helpText = document.getElementById('roleHelpText');
                if (this.value === 'admin' || this.value === 'manager') {
                    helpText.innerHTML = '<span class="text-info"><i class="fas fa-info-circle"></i> This role has access to Employee Management</span>';
                } else {
                    helpText.innerHTML = '<span class="text-secondary"><i class="fas fa-info-circle"></i> This role cannot access Employee Management</span>';
                }
            });
        }
    </script>
</body>
</html>
""", app_name=APP_NAME, employees_list=employees_list, branches=branches, user_role=session.get("user_role"))

# ------------------- Reports -------------------
@app.route("/reports")
@login_required
@role_required(["admin", "manager"])
def reports():
    branch_id = session.get("branch_id")
    user_role = session.get("user_role")
    
    # Get all branches for admin users (for branch comparison)
    all_branches = []
    if user_role == 'admin':
        # Get branches and convert them to dictionaries
        branches_rows = query_db("SELECT * FROM branches ORDER BY name")
        all_branches = []
        
        for branch_row in branches_rows:
            # Convert Row object to dictionary
            branch = dict(branch_row)
            
            # Initialize empty metrics structure
            branch['metrics'] = {
                'sales': {'total_sales': 0, 'transaction_count': 0, 'today_sales': 0, 'monthly_sales': 0},
                'inventory': {'item_count': 0, 'inventory_value': 0, 'low_stock_count': 0},
                'rtt': {'total_operations': 0, 'total_quantity': 0, 'today_operations': 0},
                'employee_count': 0
            }
            
            # Get branch metrics using the utility function
            branch_info = get_branch_info(branch['id'])
            if branch_info and 'metrics' in branch_info:
                branch['metrics'] = branch_info['metrics']
                
            all_branches.append(branch)
    
    # Get date range filters
    date_from = request.args.get("date_from", datetime.date.today().replace(day=1).isoformat())
    date_to = request.args.get("date_to", datetime.date.today().isoformat())
    
    # Sales summary by category
    sales_summary = query_db("""
        SELECT 
            i.category,
            COUNT(*) as transaction_count,
            SUM(s.quantity) as total_quantity,
            SUM(s.total_price) as total_revenue,
            AVG(s.unit_price) as avg_price
        FROM sales s
        JOIN inventory i ON s.product_id = i.id
        WHERE s.branch_id = ? AND date(s.sale_date) BETWEEN ? AND ?
        GROUP BY i.category
        ORDER BY total_revenue DESC
    """, (branch_id, date_from, date_to))
    
    # Sales by product
    sales_by_product = query_db("""
        SELECT 
            i.name,
            i.category,
            COUNT(*) as transaction_count,
            SUM(s.quantity) as total_quantity,
            SUM(s.total_price) as total_revenue
        FROM sales s
        JOIN inventory i ON s.product_id = i.id
        WHERE s.branch_id = ? AND date(s.sale_date) BETWEEN ? AND ?
        GROUP BY i.name, i.category
        ORDER BY total_revenue DESC
        LIMIT 10
    """, (branch_id, date_from, date_to))
    
    # Sales by payment method
    sales_by_payment = query_db("""
        SELECT 
            payment_method,
            COUNT(*) as transaction_count,
            SUM(total_price) as total_amount
        FROM sales
        WHERE branch_id = ? AND date(sale_date) BETWEEN ? AND ?
        GROUP BY payment_method
        ORDER BY total_amount DESC
    """, (branch_id, date_from, date_to))
    
    # Daily sales trend
    daily_sales = query_db("""
        SELECT 
            date(sale_date) as sale_day,
            SUM(total_price) as daily_total
        FROM sales
        WHERE branch_id = ? AND date(sale_date) BETWEEN ? AND ?
        GROUP BY date(sale_date)
        ORDER BY date(sale_date)
    """, (branch_id, date_from, date_to))
    
    # Top customers
    top_customers = query_db("""
        SELECT 
            c.name,
            COUNT(*) as transaction_count,
            SUM(s.total_price) as total_spent
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        WHERE s.branch_id = ? AND date(s.sale_date) BETWEEN ? AND ?
        GROUP BY c.name
        ORDER BY total_spent DESC
        LIMIT 5
    """, (branch_id, date_from, date_to))
    
    # Expense summary
    expense_summary = query_db("""
        SELECT 
            category,
            COUNT(*) as expense_count,
            SUM(amount) as total_amount
        FROM expenses
        WHERE branch_id = ? AND date(expense_date) BETWEEN ? AND ?
        GROUP BY category
        ORDER BY total_amount DESC
    """, (branch_id, date_from, date_to))
    
    # RTT Operations Summary
    rtt_summary = query_db("""
        SELECT 
            COUNT(*) as total_operations,
            SUM(quantity) as total_quantity,
            AVG(quantity) as avg_quantity
        FROM rtt_operations
        WHERE branch_id = ? AND date(timestamp) BETWEEN ? AND ?
    """, (branch_id, date_from, date_to), one=True)
    
    # Handle case where no RTT operations exist
    if not rtt_summary or rtt_summary['total_operations'] is None:
        rtt_summary = {
            'total_operations': 0,
            'total_quantity': 0,
            'avg_quantity': 0
        }
    
    # RTT by Product
    rtt_by_product = query_db("""
        SELECT 
            i.name as product_name,
            COUNT(*) as operation_count,
            SUM(r.quantity) as total_quantity
        FROM rtt_operations r
        JOIN inventory i ON r.product_id = i.id
        WHERE r.branch_id = ? AND date(r.timestamp) BETWEEN ? AND ?
        GROUP BY i.name
        ORDER BY total_quantity DESC
    """, (branch_id, date_from, date_to))
    
    # RTT by Reason
    rtt_by_reason = query_db("""
        SELECT 
            reason,
            COUNT(*) as operation_count,
            SUM(quantity) as total_quantity
        FROM rtt_operations
        WHERE branch_id = ? AND date(timestamp) BETWEEN ? AND ?
        GROUP BY reason
        ORDER BY total_quantity DESC
    """, (branch_id, date_from, date_to))
    
    # Handle empty results
    if not rtt_by_product:
        rtt_by_product = []
    if not rtt_by_reason:
        rtt_by_reason = []
    
    # Net profit calculation
    total_revenue = sum(s["total_revenue"] for s in sales_summary) if sales_summary else 0
    total_expenses = sum(e["total_amount"] for e in expense_summary) if expense_summary else 0
    net_profit = total_revenue - total_expenses
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Reports - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .summary-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .filter-section {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .chart-container {
            height: 300px;
            margin-bottom: 20px;
        }
        .profit-positive {
            color: #28a745;
        }
        .profit-negative {
            color: #dc3545;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link active">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" data-bs-toggle="dropdown">
                            <div class="user-avatar me-2">
                                {{ session.get('username', 'U')[0].upper() }}
                            </div>
                            <span>{{ session.get('username', 'User') }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user-circle me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>
        
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Reports & Analytics</h2>
            <div>
                <button class="btn btn-outline-primary" onclick="window.print()">
                    <i class="fas fa-print me-2"></i>Print Report
                </button>
            </div>
        </div>
            
            <!-- Date Filters -->
            <div class="filter-section">
                <form method="get" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" class="form-control" name="date_from" value="{{ date_from }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" class="form-control" name="date_to" value="{{ date_to }}">
                    </div>
                    <div class="col-md-3 align-self-end">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-filter me-2"></i>Apply Filters
                        </button>
                    </div>
                    <div class="col-md-3 align-self-end">
                        <a href="{{ url_for('reports') }}" class="btn btn-outline-secondary w-100">
                            <i class="fas fa-times me-2"></i>Reset
                        </a>
                    </div>
                </form>
            </div>
            
            <!-- Summary Cards -->
            <div class="row mb-4">
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-primary h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-primary text-uppercase mb-1">
                                        Total Revenue
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(total_revenue) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-dollar-sign text-primary"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-success h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-success text-uppercase mb-1">
                                        Total Expenses
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(total_expenses) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-receipt text-success"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-info h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-info text-uppercase mb-1">
                                        Transactions
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        {{ sales_summary|sum(attribute='transaction_count') or 0 }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-shopping-cart text-info"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="summary-card card border-left-{% if net_profit >= 0 %}success{% else %}danger{% endif %} h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-{% if net_profit >= 0 %}success{% else %}danger{% endif %} text-uppercase mb-1">
                                        Net Profit
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold {% if net_profit >= 0 %}profit-positive{% else %}profit-negative{% endif %}">
                                        UGX {{ "{:,.0f}".format(net_profit) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-chart-line text-{% if net_profit >= 0 %}success{% else %}danger{% endif %}"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Sales Charts -->
            <div class="row mb-4">
                <div class="col-md-6 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Sales by Category</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="categoryChart"></canvas>
                            </div>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Category</th>
                                            <th>Transactions</th>
                                            <th>Quantity</th>
                                            <th>Revenue</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for cat in sales_summary %}
                                        <tr>
                                            <td>{{ cat.category|title }}</td>
                                            <td>{{ cat.transaction_count }}</td>
                                            <td>{{ "%.2f"|format(cat.total_quantity) }}</td>
                                            <td>UGX {{ "{:,.0f}".format(cat.total_revenue) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="4" class="text-center">No sales data</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Daily Sales Trend</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="dailySalesChart"></canvas>
                            </div>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Amount</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for day in daily_sales %}
                                        <tr>
                                            <td>{{ day.sale_day }}</td>
                                            <td>UGX {{ "{:,.0f}".format(day.daily_total) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="2" class="text-center">No daily sales data</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            {% if user_role == 'admin' and all_branches|length > 0 %}
            <!-- Branch Comparison -->
            <div class="card mb-4">
                <div class="card-header bg-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Branch Performance Comparison</h5>
                    <a href="{{ url_for('branch_management') }}" class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-cog me-2"></i>Manage Branches
                    </a>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Branch</th>
                                    <th>Monthly Sales</th>
                                    <th>Transactions</th>
                                    <th>Inventory Value</th>
                                    <th>Low Stock Items</th>
                                    <th>Employees</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for branch in all_branches %}
                                <tr>
                                    <td>
                                        <span {% if branch.id == session.branch_id %}class="fw-bold"{% endif %}>
                                            {{ branch.name }}
                                            {% if branch.id == session.branch_id %}
                                            <span class="badge bg-primary">Current</span>
                                            {% endif %}
                                        </span>
                                    </td>
                                    <td>UGX {{ "{:,.0f}".format(branch['metrics']['sales']['monthly_sales'] or 0) }}</td>
                                    <td>{{ branch['metrics']['sales']['transaction_count'] or 0 }}</td>
                                    <td>UGX {{ "{:,.0f}".format(branch['metrics']['inventory']['inventory_value'] or 0) }}</td>
                                    <td>
                                        {% if branch['metrics']['inventory']['low_stock_count'] > 0 %}
                                        <span class="badge bg-warning">{{ branch['metrics']['inventory']['low_stock_count'] }}</span>
                                        {% else %}
                                        <span class="badge bg-success">0</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ branch['metrics']['employee_count'] }}</td>
                                    <td>
                                        <div class="btn-group btn-group-sm" role="group">
                                            {% if branch.id != session.branch_id %}
                                            <a href="{{ url_for('switch_branch', branch_id=branch.id) }}" class="btn btn-outline-primary">
                                                <i class="fas fa-exchange-alt"></i>
                                            </a>
                                            {% endif %}
                                            <button class="btn btn-outline-info" data-bs-toggle="modal" 
                                                    data-bs-target="#branchDetailsModal{{ branch.id }}">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                
                                <!-- Branch Details Modal -->
                                <div class="modal fade" id="branchDetailsModal{{ branch.id }}" tabindex="-1">
                                    <div class="modal-dialog modal-lg">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">{{ branch.name }} - Branch Details</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                            </div>
                                            <div class="modal-body">
                                                <div class="row mb-3">
                                                    <div class="col-md-6">
                                                        <div class="mb-3">
                                                            <small class="text-muted">Location:</small>
                                                            <p>{{ branch.location or 'Not specified' }}</p>
                                                        </div>
                                                        <div class="mb-3">
                                                            <small class="text-muted">Contact:</small>
                                                            <p>{{ branch.contact or 'Not specified' }}</p>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-6">
                                                        <div class="mb-3">
                                                            <small class="text-muted">Employees:</small>
                                                            <p>{{ branch['metrics']['employee_count'] }}</p>
                                                        </div>
                                                        <div class="mb-3">
                                                            <small class="text-muted">Inventory Items:</small>
                                                            <p>{{ branch['metrics']['inventory']['item_count'] or 0 }}</p>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <h6 class="mt-4 mb-3">Performance Metrics</h6>
                                                <div class="row g-3">
                                                    <div class="col-md-3">
                                                        <div class="p-3 border rounded bg-light">
                                                            <div class="small text-muted">Today's Sales</div>
                                                            <div class="h5">UGX {{ "{:,.0f}".format(branch['metrics']['sales']['today_sales'] or 0) }}</div>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-3">
                                                        <div class="p-3 border rounded bg-light">
                                                            <div class="small text-muted">Monthly Sales</div>
                                                            <div class="h5">UGX {{ "{:,.0f}".format(branch['metrics']['sales']['monthly_sales'] or 0) }}</div>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-3">
                                                        <div class="p-3 border rounded bg-light">
                                                            <div class="small text-muted">Total Sales</div>
                                                            <div class="h5">UGX {{ "{:,.0f}".format(branch['metrics']['sales']['total_sales'] or 0) }}</div>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-3">
                                                        <div class="p-3 border rounded bg-light">
                                                            <div class="small text-muted">Transactions</div>
                                                            <div class="h5">{{ branch['metrics']['sales']['transaction_count'] or 0 }}</div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="modal-footer">
                                                {% if branch.id != session.branch_id %}
                                                <a href="{{ url_for('switch_branch', branch_id=branch.id) }}" class="btn btn-primary">
                                                    <i class="fas fa-exchange-alt me-2"></i>Switch to Branch
                                                </a>
                                                {% endif %}
                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            {% endif %}
            
            <!-- Additional Reports -->
            <div class="row">
                <div class="col-md-4 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Top Products</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="productChart"></canvas>
                            </div>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Product</th>
                                            <th>Revenue</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for product in sales_by_product %}
                                        <tr>
                                            <td>{{ product.name }}</td>
                                            <td>UGX {{ "{:,.0f}".format(product.total_revenue) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="2" class="text-center">No product data</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Payment Methods</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="paymentChart"></canvas>
                            </div>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Method</th>
                                            <th>Amount</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for method in sales_by_payment %}
                                        <tr>
                                            <td>{{ method.payment_method|replace('_', ' ')|title }}</td>
                                            <td>UGX {{ "{:,.0f}".format(method.total_amount) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="2" class="text-center">No payment data</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Top Customers</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="customerChart"></canvas>
                            </div>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Customer</th>
                                            <th>Amount</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for customer in top_customers %}
                                        <tr>
                                            <td>{{ customer.name }}</td>
                                            <td>UGX {{ "{:,.0f}".format(customer.total_spent) }}</td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="2" class="text-center">No customer data</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Expense Report -->
            <div class="card mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Expense Breakdown</h5>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="expenseChart"></canvas>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Category</th>
                                    <th>Count</th>
                                    <th>Amount</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for exp in expense_summary %}
                                <tr>
                                    <td>{{ exp.category|replace('_', ' ')|title }}</td>
                                    <td>{{ exp.expense_count }}</td>
                                    <td>UGX {{ "{:,.0f}".format(exp.total_amount) }}</td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="3" class="text-center">No expense data</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        const categoryChart = new Chart(categoryCtx, {
            type: 'doughnut',
            data: {
                labels: [{% for cat in sales_summary %}'{{ cat.category|title }}',{% endfor %}],
                datasets: [{
                    data: [{% for cat in sales_summary %}{{ cat.total_revenue }},{% endfor %}],
                    backgroundColor: [
                        '#1e3c72', '#2a5298', '#4b6cb7', '#6a8fd8', '#8eb1ff'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Daily Sales Chart
        const dailySalesCtx = document.getElementById('dailySalesChart').getContext('2d');
        const dailySalesChart = new Chart(dailySalesCtx, {
            type: 'line',
            data: {
                labels: [{% for day in daily_sales %}'{{ day.sale_day }}',{% endfor %}],
                datasets: [{
                    label: 'Daily Sales',
                    data: [{% for day in daily_sales %}{{ day.daily_total }},{% endfor %}],
                    backgroundColor: 'rgba(30, 60, 114, 0.1)',
                    borderColor: '#1e3c72',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Product Chart
        const productCtx = document.getElementById('productChart').getContext('2d');
        const productChart = new Chart(productCtx, {
            type: 'bar',
            data: {
                labels: [{% for product in sales_by_product %}'{{ product.name }}',{% endfor %}],
                datasets: [{
                    label: 'Revenue',
                    data: [{% for product in sales_by_product %}{{ product.total_revenue }},{% endfor %}],
                    backgroundColor: '#2a5298'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Payment Chart
        const paymentCtx = document.getElementById('paymentChart').getContext('2d');
        const paymentChart = new Chart(paymentCtx, {
            type: 'pie',
            data: {
                labels: [{% for method in sales_by_payment %}'{{ method.payment_method|replace('_', ' ')|title }}',{% endfor %}],
                datasets: [{
                    data: [{% for method in sales_by_payment %}{{ method.total_amount }},{% endfor %}],
                    backgroundColor: [
                        '#28a745', '#17a2b8', '#6c757d'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
        
        // Customer Chart
        const customerCtx = document.getElementById('customerChart').getContext('2d');
        const customerChart = new Chart(customerCtx, {
            type: 'bar',
            data: {
                labels: [{% for customer in top_customers %}'{{ customer.name }}',{% endfor %}],
                datasets: [{
                    label: 'Amount Spent',
                    data: [{% for customer in top_customers %}{{ customer.total_spent }},{% endfor %}],
                    backgroundColor: '#4b6cb7'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Expense Chart
        const expenseCtx = document.getElementById('expenseChart').getContext('2d');
        const expenseChart = new Chart(expenseCtx, {
            type: 'bar',
            data: {
                labels: [{% for exp in expense_summary %}'{{ exp.category|replace('_', ' ')|title }}',{% endfor %}],
                datasets: [{
                    label: 'Amount',
                    data: [{% for exp in expense_summary %}{{ exp.total_amount }},{% endfor %}],
                    backgroundColor: '#6a8fd8'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
    </div>
</body>
</html>
""", app_name=APP_NAME, sales_summary=sales_summary, sales_by_product=sales_by_product,
   sales_by_payment=sales_by_payment, daily_sales=daily_sales, top_customers=top_customers,
   expense_summary=expense_summary, total_revenue=total_revenue, total_expenses=total_expenses,
   net_profit=net_profit, date_from=date_from, date_to=date_to, user_role=session.get("user_role"),
   all_branches=all_branches if user_role == 'admin' else [],
   rtt_summary=rtt_summary, rtt_by_product=rtt_by_product, rtt_by_reason=rtt_by_reason)

# ------------------- Fuel Deliveries -------------------
@app.route("/deliveries")
@login_required
@role_required(["admin", "manager"])
def deliveries():
    branch_id = session.get("branch_id")
    
    # Get date range filters
    date_from = request.args.get("date_from", datetime.date.today().replace(day=1).isoformat())
    date_to = request.args.get("date_to", datetime.date.today().isoformat())
    
    # Get deliveries
    deliveries = query_db("""
        SELECT d.*, i.name as product_name, s.name as supplier_name, u.username as received_by_name
        FROM fuel_deliveries d
        JOIN inventory i ON d.product_id = i.id
        LEFT JOIN suppliers s ON d.supplier_id = s.id
        LEFT JOIN users u ON d.received_by = u.id
        WHERE d.branch_id = ? AND date(d.delivery_date) BETWEEN ? AND ?
        ORDER BY d.delivery_date DESC
    """, (branch_id, date_from, date_to))
    
    # Get summary stats
    summary = query_db("""
        SELECT 
            COUNT(*) as delivery_count,
            SUM(quantity) as total_quantity,
            SUM(total_cost) as total_cost,
            AVG(unit_price) as avg_price
        FROM fuel_deliveries
        WHERE branch_id = ? AND date(delivery_date) BETWEEN ? AND ?
    """, (branch_id, date_from, date_to), one=True)
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Fuel Deliveries - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .delivery-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .delivery-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .filter-section {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link active">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" data-bs-toggle="dropdown">
                            <div class="user-avatar me-2">
                                {{ session.get('username', 'U')[0].upper() }}
                            </div>
                            <span>{{ session.get('username', 'User') }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user-circle me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>
        
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Fuel Deliveries</h2>
            <a href="{{ url_for('inventory') }}" class="btn btn-primary">
                <i class="fas fa-plus me-2"></i>Record Delivery
            </a>
        </div>
            
            <!-- Date Filters -->
            <div class="filter-section">
                <form method="get" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" class="form-control" name="date_from" value="{{ date_from }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" class="form-control" name="date_to" value="{{ date_to }}">
                    </div>
                    <div class="col-md-3 align-self-end">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-filter me-2"></i>Apply Filters
                        </button>
                    </div>
                    <div class="col-md-3 align-self-end">
                        <a href="{{ url_for('deliveries') }}" class="btn btn-outline-secondary w-100">
                            <i class="fas fa-times me-2"></i>Reset
                        </a>
                    </div>
                </form>
            </div>
            
            <!-- Summary Cards -->
            <div class="row mb-4">
                <div class="col-md-3 mb-3">
                    <div class="delivery-card card border-left-primary h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-primary text-uppercase mb-1">
                                        Deliveries
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        {{ summary.delivery_count or 0 }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-truck text-primary"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="delivery-card card border-left-success h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-success text-uppercase mb-1">
                                        Total Quantity
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        {{ "%.2f"|format(summary.total_quantity or 0) }} L
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-gas-pump text-success"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="delivery-card card border-left-info h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-info text-uppercase mb-1">
                                        Total Cost
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(summary.total_cost or 0) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-dollar-sign text-info"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-3 mb-3">
                    <div class="delivery-card card border-left-warning h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-warning text-uppercase mb-1">
                                        Avg Price/Liter
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(summary.avg_price or 0) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-tag text-warning"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Deliveries Table -->
            <div class="card">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Delivery Records</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Date</th>
                                    <th>Product</th>
                                    <th>Supplier</th>
                                    <th>Quantity</th>
                                    <th>Unit Price</th>
                                    <th>Total Cost</th>
                                    <th>Received By</th>
                                    <th>Invoice No.</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for delivery in deliveries %}
                                <tr>
                                    <td>{{ delivery.delivery_date }}</td>
                                    <td>{{ delivery.product_name }}</td>
                                    <td>{{ delivery.supplier_name or '-' }}</td>
                                    <td>{{ "%.2f"|format(delivery.quantity) }} L</td>
                                    <td>UGX {{ "{:,.0f}".format(delivery.unit_price) }}</td>
                                    <td>UGX {{ "{:,.0f}".format(delivery.total_cost) }}</td>
                                    <td>{{ delivery.received_by_name }}</td>
                                    <td>{{ delivery.invoice_number or '-' }}</td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="8" class="text-center">No delivery records found</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        </div>
    </div>
</body>
</html>
""", app_name=APP_NAME, deliveries=deliveries, summary=summary, 
   date_from=date_from, date_to=date_to, user_role=session.get("user_role"))

# ------------------- Expenses -------------------
@app.route("/expenses", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager"])
def expenses():
    branch_id = session.get("branch_id")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            # Add new expense
            try:
                category = request.form.get("category").strip()
                amount = float(request.form.get("amount", 0))
                description = request.form.get("description", "").strip()
                expense_date = request.form.get("expense_date", datetime.date.today().isoformat())
                receipt_number = request.form.get("receipt_number", "").strip()
                
                query_db("""
                    INSERT INTO expenses 
                    (branch_id, category, amount, description, expense_date, receipt_number, recorded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    branch_id, category, amount, description, expense_date, 
                    receipt_number, session["user_id"]
                ), commit=True)
                
                flash("Expense recorded successfully", "success")
                
            except Exception as e:
                flash(f"Error recording expense: {str(e)}", "danger")
                
        elif action == "update":
            # Update expense
            try:
                expense_id = int(request.form.get("expense_id"))
                category = request.form.get("category").strip()
                amount = float(request.form.get("amount", 0))
                description = request.form.get("description", "").strip()
                expense_date = request.form.get("expense_date", datetime.date.today().isoformat())
                receipt_number = request.form.get("receipt_number", "").strip()
                
                query_db("""
                    UPDATE expenses SET 
                        category = ?,
                        amount = ?,
                        description = ?,
                        expense_date = ?,
                        receipt_number = ?
                    WHERE id = ? AND branch_id = ?
                """, (
                    category, amount, description, expense_date, 
                    receipt_number, expense_id, branch_id
                ), commit=True)
                
                flash("Expense updated successfully", "success")
                
            except Exception as e:
                flash(f"Error updating expense: {str(e)}", "danger")
                
        return redirect(url_for("expenses"))
    
    # Get date range filters
    date_from = request.args.get("date_from", datetime.date.today().replace(day=1).isoformat())
    date_to = request.args.get("date_to", datetime.date.today().isoformat())
    
    # Get expenses
    expenses_list = query_db("""
        SELECT e.*, u.username as recorded_by_name
        FROM expenses e
        LEFT JOIN users u ON e.recorded_by = u.id
        WHERE e.branch_id = ? AND date(e.expense_date) BETWEEN ? AND ?
        ORDER BY e.expense_date DESC
    """, (branch_id, date_from, date_to))
    
    # Get summary stats
    summary = query_db("""
        SELECT 
            COUNT(*) as expense_count,
            SUM(amount) as total_amount,
            category,
            SUM(CASE WHEN strftime('%Y-%m', expense_date) = strftime('%Y-%m', 'now') THEN amount ELSE 0 END) as monthly_total
        FROM expenses
        WHERE branch_id = ? AND date(expense_date) BETWEEN ? AND ?
        GROUP BY category
        ORDER BY total_amount DESC
    """, (branch_id, date_from, date_to))
    
    total_expenses = sum(e["total_amount"] for e in summary) if summary else 0
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Expenses - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #1e3c72;
            --secondary: #2a5298;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
        }
        body {
            background-color: #f5f7fa;
        }
        .sidebar {
            background: linear-gradient(180deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            width: 250px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            padding: 1.5rem 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav {
            padding: 0;
            list-style: none;
        }
        .sidebar-nav-item {
            position: relative;
        }
        .sidebar-nav-link {
            display: block;
            padding: 0.75rem 1.5rem;
            color: rgba(255, 255, 255, 0.8);
            text-decoration: none;
            transition: all 0.3s;
        }
        .sidebar-nav-link:hover, .sidebar-nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .sidebar-nav-link i {
            margin-right: 0.5rem;
            width: 20px;
            text-align: center;
        }
        .main-content {
            margin-left: 250px;
            padding: 2rem;
            transition: all 0.3s;
        }
        .navbar {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0.75rem 1.5rem;
        }
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        .expense-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .expense-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .filter-section {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Expense Management</h2>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addExpenseModal">
                    <i class="fas fa-plus me-2"></i>Add Expense
                </button>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <!-- Date Filters -->
            <div class="filter-section">
                <form method="get" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" class="form-control" name="date_from" value="{{ date_from }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" class="form-control" name="date_to" value="{{ date_to }}">
                    </div>
                    <div class="col-md-3 align-self-end">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-filter me-2"></i>Apply Filters
                        </button>
                    </div>
                    <div class="col-md-3 align-self-end">
                        <a href="{{ url_for('expenses') }}" class="btn btn-outline-secondary w-100">
                            <i class="fas fa-times me-2"></i>Reset
                        </a>
                    </div>
                </form>
            </div>
            
            <!-- Summary Cards -->
            <div class="row mb-4">
                <div class="col-md-4 mb-3">
                    <div class="expense-card card border-left-primary h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-primary text-uppercase mb-1">
                                        Total Expenses
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(total_expenses) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-receipt text-primary"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-3">
                    <div class="expense-card card border-left-success h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-success text-uppercase mb-1">
                                        Expense Count
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        {{ expenses_list|length }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-list text-success"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-3">
                    <div class="expense-card card border-left-info h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col me-2">
                                    <div class="text-info text-uppercase mb-1">
                                        Avg. Expense
                                    </div>
                                    <div class="h5 mb-0 font-weight-bold">
                                        UGX {{ "{:,.0f}".format(total_expenses / expenses_list|length if expenses_list|length > 0 else 0) }}
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <i class="fas fa-calculator text-info"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Expenses Table -->
            <div class="card mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Expense Records</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Date</th>
                                    <th>Category</th>
                                    <th>Amount</th>
                                    <th>Description</th>
                                    <th>Receipt No.</th>
                                    <th>Recorded By</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for expense in expenses_list %}
                                <tr>
                                    <td>{{ expense.expense_date }}</td>
                                    <td>{{ expense.category|replace('_', ' ')|title }}</td>
                                    <td>UGX {{ "{:,.0f}".format(expense.amount) }}</td>
                                    <td>{{ expense.description or '-' }}</td>
                                    <td>{{ expense.receipt_number or '-' }}</td>
                                    <td>{{ expense.recorded_by_name }}</td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#editExpenseModal{{ expense.id }}">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                    </td>
                                </tr>
                                
                                <!-- Edit Modal -->
                                <div class="modal fade" id="editExpenseModal{{ expense.id }}" tabindex="-1">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Edit Expense</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                            </div>
                                            <form method="post">
                                                <div class="modal-body">
                                                    <input type="hidden" name="action" value="update">
                                                    <input type="hidden" name="expense_id" value="{{ expense.id }}">
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Category</label>
                                                        <input type="text" class="form-control" 
                                                               name="category" value="{{ expense.category }}" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Amount (UGX)</label>
                                                        <input type="number" step="0.01" min="0" 
                                                               class="form-control" name="amount" 
                                                               value="{{ expense.amount }}" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Description</label>
                                                        <textarea class="form-control" name="description" 
                                                                  rows="2">{{ expense.description or '' }}</textarea>
                                                    </div>
                                                    
                                                    <div class="row mb-3">
                                                        <div class="col-md-6">
                                                            <label class="form-label">Date</label>
                                                            <input type="date" class="form-control" 
                                                                   name="expense_date" value="{{ expense.expense_date }}">
                                                        </div>
                                                        <div class="col-md-6">
                                                            <label class="form-label">Receipt Number</label>
                                                            <input type="text" class="form-control" 
                                                                   name="receipt_number" value="{{ expense.receipt_number or '' }}">
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                                {% else %}
                                <tr>
                                    <td colspan="7" class="text-center">No expense records found</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Expense Breakdown -->
            <div class="card">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Expense Breakdown by Category</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Category</th>
                                    <th>Count</th>
                                    <th>Total Amount</th>
                                    <th>% of Total</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for cat in summary %}
                                <tr>
                                    <td>{{ cat.category|replace('_', ' ')|title }}</td>
                                    <td>{{ cat.expense_count }}</td>
                                    <td>UGX {{ "{:,.0f}".format(cat.total_amount) }}</td>
                                    <td>{{ "%.1f"|format((cat.total_amount / total_expenses) * 100 if total_expenses > 0 else 0) }}%</td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="4" class="text-center">No expense data</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Add Expense Modal -->
    <div class="modal fade" id="addExpenseModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Expense</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add">
                        
                        <div class="mb-3">
                            <label class="form-label">Category</label>
                            <select class="form-select" name="category" required>
                                <option value="">Select Category</option>
                                <option value="fuel_purchase">Fuel Purchase</option>
                                <option value="pump_maintenance">Pump Maintenance</option>
                                <option value="station_maintenance">Station Maintenance</option>
                                <option value="utilities">Utilities</option>
                                <option value="salaries">Salaries</option>
                                <option value="office_supplies">Office Supplies</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Amount (UGX)</label>
                            <input type="number" step="0.01" min="0" class="form-control" name="amount" required>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" name="description" rows="2"></textarea>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Date</label>
                                <input type="date" class="form-control" name="expense_date" 
                                       value="{{ datetime.date.today().isoformat() }}">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Receipt Number (optional)</label>
                                <input type="text" class="form-control" name="receipt_number">
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Expense</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, expenses_list=expenses_list, summary=summary, 
   total_expenses=total_expenses, date_from=date_from, date_to=date_to, user_role=session.get("user_role"), datetime=datetime)

# ------------------- Audit Logs -------------------
@app.route("/audit-logs")
@login_required
@role_required(["admin", "manager"])
def audit_logs():
    branch_id = session.get("branch_id")
    
    # Get date range filters
    date_from = request.args.get("date_from", datetime.date.today().replace(day=1).isoformat())
    date_to = request.args.get("date_to", datetime.date.today().isoformat())
    user_id = request.args.get("user_id", "")
    
    # Base query
    query = """
        SELECT a.*, u.username, b.name as branch_name
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN branches b ON a.branch_id = b.id
        WHERE a.branch_id = ? AND date(a.timestamp) BETWEEN ? AND ?
    """
    params = [branch_id, date_from, date_to]
    
    # Add user filter if specified
    if user_id:
        query += " AND a.user_id = ?"
        params.append(user_id)
    
    query += " ORDER BY a.timestamp DESC LIMIT 200"
    
    logs = query_db(query, params)
    
    # Get all users for filter
    users = query_db("""
        SELECT id, username FROM users 
        WHERE branch_id = ?
        ORDER BY username
    """, (branch_id,))
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Audit Logs - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .log-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .log-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .filter-section {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .log-details {
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Audit Logs</h2>
                <small>Showing last 200 records</small>
            </div>
            
            <!-- Filters -->
            <div class="filter-section">
                <form method="get" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" class="form-control" name="date_from" value="{{ date_from }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" class="form-control" name="date_to" value="{{ date_to }}">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">User</label>
                        <select class="form-select" name="user_id">
                            <option value="">All Users</option>
                            {% for user in users %}
                            <option value="{{ user.id }}" {% if user_id == user.id|string %}selected{% endif %}>
                                {{ user.username }}
                            </option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-3 align-self-end">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-filter me-2"></i>Apply Filters
                        </button>
                    </div>
                </form>
            </div>
            
            <!-- Logs Table -->
            <div class="card">
                <div class="card-header bg-white">
                    <h5 class="mb-0">System Activities</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Details</th>
                                    <th>IP Address</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for log in logs %}
                                <tr>
                                    <td>{{ log.timestamp }}</td>
                                    <td>{{ log.username or 'System' }}</td>
                                    <td>{{ log.action }}</td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-info" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#logDetailsModal{{ log.id }}">
                                            <i class="fas fa-eye"></i> View
                                        </button>
                                    </td>
                                    <td>{{ log.ip_address or '-' }}</td>
                                </tr>
                                
                                <!-- Details Modal -->
                                <div class="modal fade" id="logDetailsModal{{ log.id }}" tabindex="-1">
                                    <div class="modal-dialog modal-lg">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Log Details</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                            </div>
                                            <div class="modal-body">
                                                <div class="mb-3">
                                                    <small class="text-muted">Timestamp:</small>
                                                    <p>{{ log.timestamp }}</p>
                                                </div>
                                                
                                                <div class="mb-3">
                                                    <small class="text-muted">User:</small>
                                                    <p>{{ log.username or 'System' }}</p>
                                                </div>
                                                
                                                <div class="mb-3">
                                                    <small class="text-muted">Action:</small>
                                                    <p>{{ log.action }}</p>
                                                </div>
                                                
                                                <div class="mb-3">
                                                    <small class="text-muted">Details:</small>
                                                    <div class="log-details">
                                                        {{ log.details or 'No additional details' }}
                                                    </div>
                                                </div>
                                                
                                                <div class="mb-3">
                                                    <small class="text-muted">IP Address:</small>
                                                    <p>{{ log.ip_address or '-' }}</p>
                                                </div>
                                                
                                                <div class="mb-3">
                                                    <small class="text-muted">User Agent:</small>
                                                    <p>{{ log.user_agent or '-' }}</p>
                                                </div>
                                                
                                                <div class="mb-3">
                                                    <small class="text-muted">Branch:</small>
                                                    <p>{{ log.branch_name or '-' }}</p>
                                                </div>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                {% else %}
                                <tr>
                                    <td colspan="5" class="text-center">No audit logs found</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, logs=logs, users=users, date_from=date_from, date_to=date_to, user_id=user_id, user_role=session.get("user_role"))

# ------------------- Audit Log Utility -------------------
def add_audit_log(user_id, action, details=None, ip_address=None, user_agent=None, branch_id=None):
    query_db("""
        INSERT INTO audit_logs 
        (user_id, action, details, ip_address, user_agent, branch_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, action, details, ip_address, user_agent, branch_id), commit=True)

# ------------------- Sync Queue Utility -------------------
def add_to_sync_queue(table_name, record_id, action, record_data=None):
    if record_data is None:
        # Get the record data as JSON
        record = query_db(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,), one=True)
        if record:
            import json
            record_data = json.dumps(dict(record))
    
    query_db("""
        INSERT INTO sync_queue 
        (table_name, record_id, record_data, action)
        VALUES (?, ?, ?, ?)
    """, (table_name, record_id, record_data, action), commit=True)

@app.route("/sync", methods=["POST"])
@login_required
@role_required(["admin", "manager"])
def sync_data():
    # Placeholder: in real deployment, you'd send queued data to central server here
    unsynced = query_db("SELECT * FROM sync_queue WHERE synced = 0 ORDER BY timestamp ASC")
    if not unsynced:
        return jsonify({"status": "no_changes"})
    
    # In a real implementation, you would:
    # 1. Package the unsynced data
    # 2. Send to central server
    # 3. Mark as synced if successful
    
    # For demo purposes, we'll just mark all as synced
    for record in unsynced:
        query_db("UPDATE sync_queue SET synced = 1 WHERE id = ?", (record["id"],), commit=True)
    
    return jsonify({
        "status": "synced",
        "count": len(unsynced),
        "data": [dict(r) for r in unsynced]
    })

# ------------------- Backup and Restore -------------------
@app.route("/backup")
@login_required
@role_required(["admin", "manager"])
def backup():
    try:
        os.makedirs("backups", exist_ok=True)
        db_path = os.path.abspath(DATABASE)
        backup_name = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        backup_path = os.path.join("backups", backup_name)
        
        import shutil
        shutil.copy(db_path, backup_path)
        
        # Create a zip file for better compression
        import zipfile
        with zipfile.ZipFile(f"{backup_path}.zip", 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(backup_path, os.path.basename(backup_path))
        
        # Remove the uncompressed backup
        os.remove(backup_path)
        
        # Log the backup
        add_audit_log(
            session["user_id"], 
            "Database backup created", 
            f"Backup file: {backup_name}.zip",
            request.remote_addr,
            request.user_agent.string,
            session["branch_id"]
        )
        
        flash(f"Backup saved successfully as {backup_name}.zip", "success")
    except Exception as e:
        flash(f"Backup failed: {str(e)}", "danger")
    
    return redirect(url_for("dashboard"))

@app.route("/restore", methods=["GET", "POST"])
@login_required
@role_required(["admin", "manager"])
def restore():
    if request.method == "POST":
        file = request.files.get("backup_file")
        if file and (file.filename.endswith(".db") or file.filename.endswith(".zip")):
            try:
                # Create temp directory
                temp_dir = os.path.join("backups", "temp")
                os.makedirs(temp_dir, exist_ok=True)
                
                # Save uploaded file
                temp_path = os.path.join(temp_dir, file.filename)
                file.save(temp_path)
                
                # Handle zip files
                if file.filename.endswith(".zip"):
                    import zipfile
                    with zipfile.ZipFile(temp_path, 'r') as zipf:
                        # Extract the first .db file found
                        for name in zipf.namelist():
                            if name.endswith('.db'):
                                zipf.extract(name, temp_dir)
                                temp_path = os.path.join(temp_dir, name)
                                break
                
                # Verify the backup file
                try:
                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchall()
                    conn.close()
                    
                    required_tables = {'users', 'branches', 'inventory', 'sales', 'pumps', 'customers'}
                    existing_tables = {t[0] for t in tables}
                    
                    if not required_tables.issubset(existing_tables):
                        raise ValueError("Backup file is missing required tables")
                except Exception as e:
                    raise ValueError(f"Invalid backup file: {str(e)}")
                
                # Create a backup of current database before restore
                current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                pre_restore_backup = os.path.join("backups", f"pre_restore_{current_time}.db")
                shutil.copy(DATABASE, pre_restore_backup)
                
                # Perform the restore
                shutil.copy(temp_path, DATABASE)
                
                # Clean up
                shutil.rmtree(temp_dir)
                
                # Log the restore
                add_audit_log(
                    session["user_id"], 
                    "Database restored from backup", 
                    f"Restored from: {file.filename}",
                    request.remote_addr,
                    request.user_agent.string,
                    session["branch_id"]
                )
                
                flash("Restore successful! Please restart the application.", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                flash(f"Restore failed: {str(e)}", "danger")
        else:
            flash("Please upload a valid SQLite .db or .zip file", "warning")
        return redirect(url_for("restore"))
    
    # Get list of available backups
    backups = []
    if os.path.exists("backups"):
        for f in sorted(os.listdir("backups"), reverse=True):
            if f.endswith(".db") or f.endswith(".zip"):
                path = os.path.join("backups", f)
                size = os.path.getsize(path)
                backups.append({
                    "name": f,
                    "size": size,
                    "date": datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Restore Backup - {{app_name}}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .backup-card {
            border-radius: 10px;
            transition: all 0.3s;
        }
        .backup-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            {{app_name}}
        </div>
        <ul class="sidebar-nav">
            <li class="sidebar-nav-item">
                <a href="{{ url_for('dashboard') }}" class="sidebar-nav-link">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('quick_sale') }}" class="sidebar-nav-link">
                    <i class="fas fa-bolt"></i> Quick Sale
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('inventory') }}" class="sidebar-nav-link">
                    <i class="fas fa-gas-pump"></i> Inventory
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('sales') }}" class="sidebar-nav-link">
                    <i class="fas fa-shopping-cart"></i> Sales
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('pumps') }}" class="sidebar-nav-link">
                    <i class="fas fa-oil-can"></i> Pumps
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('customers') }}" class="sidebar-nav-link">
                    <i class="fas fa-users"></i> Customers
                </a>
            </li>
            {% if user_role in ['admin', 'manager'] %}
            <li class="sidebar-nav-item">
                <a href="{{ url_for('employees') }}" class="sidebar-nav-link">
                    <i class="fas fa-user-tie"></i> Employees
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('reports') }}" class="sidebar-nav-link">
                    <i class="fas fa-chart-bar"></i> Reports
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('deliveries') }}" class="sidebar-nav-link">
                    <i class="fas fa-truck"></i> Deliveries
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('expenses') }}" class="sidebar-nav-link">
                    <i class="fas fa-receipt"></i> Expenses
                </a>
            </li>
            <li class="sidebar-nav-item">
                <a href="{{ url_for('backup') }}" class="sidebar-nav-link">
                    <i class="fas fa-database"></i> Backup
                </a>
            </li>
            {% endif %}
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <nav class="navbar navbar-expand navbar-light mb-4">
            <div class="container-fluid">
                <button class="btn btn-link text-dark d-md-none" type="button">
                    <i class="fas fa-bars"></i>
                </button>
                
                <div class="ms-auto d-flex align-items-center">
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" 
                           id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="user-avatar me-2">
                                {{ session.username[0].upper() }}
                            </div>
                            <span>{{ session.full_name or session.username }}</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i> Profile</a></li>
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <h2 class="mb-4">Backup & Restore</h2>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for cat, msg in messages %}
                        <div class="alert alert-{{cat}} alert-dismissible fade show mb-4">{{msg}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="row">
                <div class="col-md-6 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Create New Backup</h5>
                        </div>
                        <div class="card-body">
                            <p>Create a complete backup of the current database.</p>
                            <div class="d-grid">
                                <a href="{{ url_for('backup') }}" class="btn btn-primary">
                                    <i class="fas fa-database me-2"></i>Create Backup Now
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6 mb-4">
                    <div class="card h-100">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Restore from Backup</h5>
                        </div>
                        <div class="card-body">
                            <form method="post" enctype="multipart/form-data">
                                <div class="mb-3">
                                    <label class="form-label">Upload Backup File</label>
                                    <input type="file" class="form-control" name="backup_file" required 
                                           accept=".db,.zip,application/zip">
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-warning">
                                        <i class="fas fa-undo me-2"></i>Restore Database
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Available Backups</h5>
                </div>
                <div class="card-body">
                    {% if backups %}
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>File Name</th>
                                    <th>Date</th>
                                    <th>Size</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for backup in backups %}
                                <tr>
                                    <td>{{ backup.name }}</td>
                                    <td>{{ backup.date }}</td>
                                    <td>{{ "%.1f"|format(backup.size / 1024) }} KB</td>
                                    <td>
                                        <a href="{{ url_for('download_backup', filename=backup.name) }}" 
                                           class="btn btn-sm btn-outline-primary me-2">
                                            <i class="fas fa-download me-1"></i>Download
                                        </a>
                                        <form method="post" action="{{ url_for('delete_backup') }}" 
                                              class="d-inline" onsubmit="return confirm('Delete this backup?')">
                                            <input type="hidden" name="filename" value="{{ backup.name }}">
                                            <button type="submit" class="btn btn-sm btn-outline-danger">
                                                <i class="fas fa-trash me-1"></i>Delete
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i> No backup files found
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", app_name=APP_NAME, backups=backups, user_role=session.get("user_role"))

@app.route("/download-backup/<filename>")
@login_required
@role_required(["admin", "manager"])
def download_backup(filename):
    return send_from_directory("backups", filename, as_attachment=True)

@app.route("/delete-backup", methods=["POST"])
@login_required
@role_required(["admin", "manager"])
def delete_backup():
    filename = request.form.get("filename")
    if not filename or not filename.endswith(('.db', '.zip')):
        flash("Invalid filename", "danger")
        return redirect(url_for("restore"))
    
    try:
        filepath = os.path.join("backups", filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            
            # Log the deletion
            add_audit_log(
                session["user_id"], 
                "Backup file deleted", 
                f"Deleted file: {filename}",
                request.remote_addr,
                request.user_agent.string,
                session["branch_id"]
            )
            
            flash("Backup file deleted successfully", "success")
        else:
            flash("File not found", "warning")
    except Exception as e:
        flash(f"Error deleting file: {str(e)}", "danger")
    
    return redirect(url_for("restore"))

# ------------------- Receipt Printing -------------------
def print_receipt(sale, product):
    if not ESC_POS_AVAILABLE:
        print("ESC/POS printing library not installed or printer not configured.")
        return
    
    try:
        # Open USB printer (adjust vendor/product IDs for your printer)
        p = Usb(USB_VENDOR_ID, USB_PRODUCT_ID, 0)
        
        # Print header
        p.set(align='center', font='a', width=2, height=2)
        p.text(f"{APP_NAME}\n")
        p.set(align='center', font='a', width=1, height=1)
        p.text("Fuel & Lubricants Sale Receipt\n")
        p.text("------------------------------\n")
        
        # Print receipt details
        p.set(align='left')
        p.text(f"Date: {sale['sale_date']}\n")
        p.text(f"Receipt #: {sale['receipt_number']}\n")
        p.text("------------------------------\n")
        
        # Print product details
        p.set(align='left')
        p.text(f"Product: {product['name']}\n")
        p.text(f"Quantity: {sale['quantity']} {product['unit']}\n")
        p.text(f"Unit Price: UGX {sale['unit_price']:.2f}\n")
        
        if sale['discount'] > 0:
            p.text(f"Discount: {sale['discount']}%\n")
        
        p.text("------------------------------\n")
        
        # Print total
        p.set(align='left', width=2, height=2)
        p.text(f"TOTAL: UGX {sale['total_price']:.2f}\n")
        p.set(align='left', width=1, height=1)
        
        # Print payment method
        p.text(f"Payment Method: {sale['payment_method'].replace('_', ' ').title()}\n")
        
        # Print customer information if available
        if sale['customer_name']:
            p.text(f"Customer: {sale['customer_name']}\n")
        
        # Print vehicle registration if available in notes
        if sale.get('notes') and 'Vehicle:' in sale['notes']:
            vehicle_reg = sale['notes'].replace('Vehicle: ', '')
            p.text(f"Vehicle: {vehicle_reg}\n")
        
        # Print footer
        p.text("------------------------------\n")
        p.set(align='center')
        p.text("Thank you for your business!\n")
        p.text(f"Branch: {session.get('branch_name', 'N/A')}\n")
        p.text(f"Attendant: {session.get('username', 'System')}\n")
        p.text("\n\n\n")
        
        # Cut paper
        p.cut()
        
    except Exception as e:
        print(f"Printing failed: {e}")
        # Log the error
        add_audit_log(
            session.get("user_id"), 
            "Receipt printing failed", 
            str(e),
            request.remote_addr if 'request' in globals() else None,
            request.user_agent.string if 'request' in globals() else None,
            session.get("branch_id")
        )

# ------------------- Custom Filters -------------------
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try:
            value = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                value = datetime.datetime.strptime(value, '%Y-%m-%d')
            except ValueError:
                return value
    return value.strftime(format)

# ------------------- Register RTT Operation Route -------------------
# Register the RTT operation route
add_rtt_operation_route(app, query_db, add_audit_log, APP_NAME, role_required, login_required)

# ------------------- Main Runner -------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HEM Petroleum Management System")
    parser.add_argument("--initdb", action="store_true", help="Initialize database")
    parser.add_argument("--host", default="127.0.0.1", help="Host to run server on")
    parser.add_argument("--port", default=5000, type=int, help="Port to run server on")
    args = parser.parse_args()

    if args.initdb:
        create_tables()
        print("Database initialized successfully.")
    
        # Print instructions for logo usage
        print("\nLogo setup completed!")
        print("A default logo has been created at: static/logo.svg")
        print("You can replace this file with your own logo while keeping the same name.")
        print("The logo will be displayed in the application automatically.")
    else:
        app.run(host=args.host, port=args.port, debug=False)