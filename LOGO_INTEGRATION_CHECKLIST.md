# Logo Integration Checklist

## Files Created
1. `logo_integration.py` - Core functionality for logo integration
2. `logo_integration_example.py` - Example of how to integrate in the main app

## Steps to Integrate Logo System-Wide

### Step 1: Verify Logo Files
- [ ] Ensure logo files are in the correct location: `static/images/`
- [ ] Primary logo file should be named `logo.png`
- [ ] Alternative formats can be named `logo.jpg`, `logo.svg`, or `logo.gif`

### Step 2: Update Main Application
- [ ] In `hem_petroleum.py`, add this import at the top:
  ```python
  from logo_integration import integrate_logo_system, update_template_with_logo
  ```

- [ ] After creating your Flask app instance, add:
  ```python
  integrate_logo_system(app, APP_NAME)
  ```

### Step 3: Update All Template Rendering
- [ ] For direct template strings in `hem_petroleum.py`, wrap them with:
  ```python
  template = """Your HTML template"""
  template = update_template_with_logo(template)
  return render_template_string(template, ...)
  ```

- [ ] For templates in imported modules (like `rtt_operations.py`):
  - [ ] Uncomment the import line: `from logo_integration import update_template_with_logo`
  - [ ] Uncomment the function call: `template = update_template_with_logo(template)`

### Step 4: Test Logo Appearance
- [ ] Login page: Logo should appear above the login form
- [ ] Dashboard: Logo should appear in sidebar and navbar
- [ ] All other pages: Logo should appear consistently

### Step 5: Update Custom CSS (if needed)
- [ ] If you have custom styling for logos, review and adjust the CSS in `logo_integration.py`

## Usage in Templates

The system makes the following variables available in all templates:

1. `{{ logo_html_small }}` - Small logo (32px height)
2. `{{ logo_html_default }}` - Default logo (60px height)
3. `{{ logo_html_large }}` - Large logo (80px height)
4. `{{ get_logo_html("size", "extra-classes", "alt text") }}` - Custom logo

5. `{{ logo_css }}` - CSS styles for logos
6. `{{ favicon_url }}` - URL to favicon image

## Example Usage in Custom Templates

```html
<!-- In <head> section -->
{{ logo_css }}
<link rel="icon" href="{{ favicon_url }}" type="image/png">

<!-- In sidebar -->
<div class="sidebar-brand">
  {{ logo_html_default }}
  <div class="sidebar-brand-text">{{ app_name }}</div>
</div>

<!-- In navbar -->
<div class="navbar-brand-container">
  {{ logo_html_small }}
  <span class="fw-bold">{{ app_name }}</span>
</div>

<!-- Custom sizing and classes -->
{{ get_logo_html("large", "rounded shadow", "Company Logo") }}
```

## Troubleshooting
1. If logos don't appear, check browser console for 404 errors
2. Verify the static folder is configured correctly in Flask
3. Make sure file permissions allow web server to access images
4. Try clearing browser cache if changes don't appear
