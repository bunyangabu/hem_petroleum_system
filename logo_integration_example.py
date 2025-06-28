# Example Integration in your main Flask application (hem_petroleum.py)

# Import the logo integration functions
from logo_integration import integrate_logo_system, update_template_with_logo

def setup_logo_in_main_app(app, APP_NAME):
    """Add this to your hem_petroleum.py file to set up the logo system"""
    
    # Initialize the logo system
    integrate_logo_system(app, APP_NAME)
    
    # For any route that uses render_template_string directly, update the template
    # Example for your login route:
    @app.route("/login", methods=["GET", "POST"])
    def login():
        # Your existing login code...
        
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - {{app_name}}</title>
            <!-- Other head elements -->
        </head>
        <body>
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-md-6 col-lg-5">
                        <div class="card shadow-sm border-0 rounded-lg mt-5">
                            <div class="card-body">
                                <!-- The logo will be automatically inserted here by the update_template_with_logo function -->
                                <form method="post">
                                    <!-- Your form fields -->
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Update the template with logo integration
        template = update_template_with_logo(template)
        
        return render_template_string(template, app_name=APP_NAME, etc...)

# INSTALLATION INSTRUCTIONS:

# 1. In hem_petroleum.py, import the logo integration:
#    from logo_integration import integrate_logo_system, update_template_with_logo

# 2. After creating your Flask app, add:
#    integrate_logo_system(app, APP_NAME)

# 3. For any routes using render_template_string, update:
#    template = """..."""
#    template = update_template_with_logo(template)
#    return render_template_string(template, ...)

# 4. For your routes imported from modules like rtt_operations.py:
#    - Uncomment the import line in each module
#    - Uncomment the template = update_template_with_logo(template) line

# 5. Make sure your logo files are in static/images/ folder named:
#    - logo.png (primary)
#    - logo.jpg, logo.svg, or logo.gif (fallbacks)
