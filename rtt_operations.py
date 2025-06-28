# RTT Operations for HEM Petroleum
from flask import request, session, redirect, url_for, flash, render_template_string

# Import the logo integration functionality (import this in main app)
# from logo_integration import update_template_with_logo

# This function should be imported in the main application
def add_rtt_operation_route(app, query_db, add_audit_log, APP_NAME, role_required, login_required):
    @app.route("/rtt_operation", methods=["GET", "POST"])
    @login_required
    @role_required(["admin", "manager", "attendant"])
    def rtt_operation():
        branch_id = session.get("branch_id")
        
        # Get all products for this branch
        products = query_db("""
            SELECT * FROM inventory 
            WHERE branch_id = ? AND category = 'fuel'
            ORDER BY name
        """, (branch_id,))
        
        # Get all pumps for this branch
        try:
            pumps = query_db("""
                SELECT p.*, i.name as product_name 
                FROM pumps p
                LEFT JOIN inventory i ON p.product_id = i.id
                WHERE p.branch_id = ? AND (p.status = 'active' OR p.status IS NULL)
                ORDER BY p.pump_number
            """, (branch_id,))
        except Exception as e:
            # Fallback query if product_id column doesn't exist yet
            pumps = query_db("""
                SELECT p.*, NULL as product_name 
                FROM pumps p
                WHERE p.branch_id = ? AND (p.status = 'active' OR p.status IS NULL)
                ORDER BY p.pump_number
            """, (branch_id,))
        
        if request.method == "POST":
            # Process the RTT operation form
            product_id = request.form.get("product_id", type=int)
            pump_number = request.form.get("pump_number", type=int)
            quantity = request.form.get("quantity", type=float)
            reason = request.form.get("reason")
            
            # Validate inputs
            if not product_id or not pump_number or not quantity or quantity <= 0:
                flash("All fields are required and quantity must be greater than zero", "danger")
                return redirect(url_for("rtt_operation"))
            
            # Record the RTT operation
            query_db("""
                INSERT INTO rtt_operations 
                (branch_id, product_id, pump_number, quantity, reason, employee_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (branch_id, product_id, pump_number, quantity, reason, session.get("user_id")), commit=True)
            
            # Update inventory (increase stock)
            query_db("""
                UPDATE inventory
                SET quantity = quantity + ?
                WHERE id = ? AND branch_id = ?
            """, (quantity, product_id, branch_id), commit=True)
            
            # Log the operation
            product_name = next((p["name"] for p in products if p["id"] == product_id), "Unknown")
            add_audit_log(
                session["user_id"],
                "RTT Operation",
                f"Product: {product_name}, Pump: {pump_number}, Quantity: {quantity}, Reason: {reason}",
                request.remote_addr,
                request.user_agent.string,
                branch_id
            )
            
            flash("RTT operation recorded successfully", "success")
            return redirect(url_for("rtt_operation"))
        
        # Get recent RTT operations
        rtt_history = query_db("""
            SELECT r.*, i.name as product_name, u.username as employee_name
            FROM rtt_operations r
            JOIN inventory i ON r.product_id = i.id
            LEFT JOIN users u ON r.employee_id = u.id
            WHERE r.branch_id = ?
            ORDER BY r.timestamp DESC
            LIMIT 20
        """, (branch_id,))
        
        # Get the template string
        template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Return to Tank Operations - {{app_name}}</title>
        <link rel="icon" href="{{ url_for('static', filename='images/logo.png') }}" type="image/png">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <script>
        function handleLogoError(img) {
            if (img.src.includes('logo.png')) {
                img.src = img.src.replace('logo.png', 'logo.jpg');
            } else if (img.src.includes('logo.jpg')) {
                img.src = img.src.replace('logo.jpg', 'logo.svg');
            } else if (img.src.includes('logo.svg')) {
                img.src = img.src.replace('logo.svg', 'logo.gif');
            } else {
                img.style.display = 'none';
                img.parentElement.innerHTML = '<div style="color: white; font-weight: bold;">{{app_name}}</div>';
            }
        }
        </script>
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
                text-align: center;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 0.5rem;
            }
            /* Logo styling is now handled by the logo integration system */
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
            /* Navbar logo styling is now handled by the logo integration system */
        </style>
    </head>
    <body>
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-brand">
                <img src="{{ url_for('static', filename='images/logo.png') }}" 
                     alt="{{app_name}}" 
                     style="max-height: 60px; max-width: 120px; object-fit: contain; margin-bottom: 8px;"
                     onerror="handleLogoError(this)">
                <div style="font-size: 1.2rem; font-weight: 600;">{{app_name}}</div>
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
                    <a href="{{ url_for('rtt_operation') }}" class="sidebar-nav-link active">
                        <i class="fas fa-exchange-alt"></i> Return to Tank
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
                    
                    <div class="d-none d-md-flex align-items-center">
                        <img src="{{ url_for('static', filename='images/logo.png') }}" 
                             alt="{{app_name}}" 
                             style="max-height: 32px; max-width: 100px; object-fit: contain; margin-right: 8px;"
                             onerror="handleLogoError(this)">
                        <span class="fw-bold">{{app_name}}</span>
                    </div>
                    
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
                    <h2><i class="fas fa-exchange-alt me-2"></i> Return to Tank Operations</h2>
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
                    <!-- RTT Form -->
                    <div class="col-md-5 mb-4">
                        <div class="card">
                            <div class="card-header bg-white">
                                <h5 class="mb-0">New RTT Operation</h5>
                            </div>
                            <div class="card-body">
                                <form method="post">
                                    <div class="mb-3">
                                        <label class="form-label">Product</label>
                                        <select name="product_id" class="form-select" required>
                                            <option value="">-- Select Product --</option>
                                            {% for product in products %}
                                            <option value="{{ product.id }}">{{ product.name }}</option>
                                            {% endfor %}
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Pump Number</label>
                                        <select name="pump_number" class="form-select" required>
                                            <option value="">-- Select Pump --</option>
                                            {% for pump in pumps %}
                                            <option value="{{ pump.pump_number }}">
                                                Pump {{ pump.pump_number }} - {{ pump.product_name }}
                                            </option>
                                            {% endfor %}
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Quantity (Liters)</label>
                                        <input type="number" step="0.01" min="0.01" class="form-control" 
                                               name="quantity" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Reason</label>
                                        <select name="reason" class="form-select" required>
                                            <option value="">-- Select Reason --</option>
                                            <option value="Pump Calibration">Pump Calibration</option>
                                            <option value="Pipe Maintenance">Pipe Maintenance</option>
                                            <option value="Pump Maintenance">Pump Maintenance</option>
                                            <option value="Testing">Testing</option>
                                            <option value="Unusable Fuel">Unusable Fuel</option>
                                            <option value="Other">Other</option>
                                        </select>
                                    </div>
                                    
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="fas fa-save me-2"></i>Record RTT Operation
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <!-- RTT History -->
                    <div class="col-md-7 mb-4">
                        <div class="card">
                            <div class="card-header bg-white">
                                <h5 class="mb-0">Recent RTT Operations</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Date & Time</th>
                                                <th>Product</th>
                                                <th>Pump</th>
                                                <th>Quantity</th>
                                                <th>Reason</th>
                                                <th>Employee</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for op in rtt_history %}
                                            <tr>
                                                <td>{{ op.timestamp }}</td>
                                                <td>{{ op.product_name }}</td>
                                                <td>{{ op.pump_number }}</td>
                                                <td>{{ "%.2f"|format(op.quantity) }} L</td>
                                                <td>{{ op.reason }}</td>
                                                <td>{{ op.employee_name }}</td>
                                            </tr>
                                            {% else %}
                                            <tr>
                                                <td colspan="6" class="text-center">No RTT operations recorded</td>
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
    """
        
        # Update the template to include the logo (uncommment this when integrated with main app)
        # template = update_template_with_logo(template)
        
        return render_template_string(template, app_name=APP_NAME, 
                                     products=products, pumps=pumps, 
                                     rtt_history=rtt_history, 
                                     user_role=session.get("user_role"))
        
    return rtt_operation
