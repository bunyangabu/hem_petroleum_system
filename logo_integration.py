# Simple Logo Integration for HEM Petroleum System
from flask import url_for

def add_logo_to_app(app):
    """
    Simple logo integration that adds logo context to all templates
    """
    @app.context_processor
    def inject_logo():
        return {
            'logo_png': url_for('static', filename='images/logo.png'),
            'logo_jpg': url_for('static', filename='images/logo.jpg'),
            'logo_svg': url_for('static', filename='images/logo.svg'),
            'logo_gif': url_for('static', filename='images/logo.gif'),
        }

def get_logo_fallback_script():
    """
    Returns JavaScript code for logo fallback handling
    """
    return """
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
        }
    }
    </script>
    """

def get_simple_logo_html(size="default"):
    """
    Returns simple logo HTML that works with Flask url_for in templates
    """
    if size == "small":
        style = "max-height: 32px; max-width: 100px; object-fit: contain;"
    elif size == "large":
        style = "max-height: 80px; max-width: 160px; object-fit: contain;"
    else:
        style = "max-height: 60px; max-width: 120px; object-fit: contain;"
    
    return f'''<img src="{{{{ logo_png }}}}" alt="{{{{app_name}}}}" style="{style}" onerror="handleLogoError(this)">'''
# Example of how to add this to your main app:
# 
# In hem_petroleum.py, add this after creating your Flask app:
# 
# from logo_integration import add_logo_to_app
# add_logo_to_app(app)
#
# Then in any template, you can use:
# <img src="{{ logo_png }}" alt="{{app_name}}" style="max-height: 60px;" onerror="handleLogoError(this)">
#
# Don't forget to include the fallback script in your templates:
# {{ get_logo_fallback_script()|safe }}
