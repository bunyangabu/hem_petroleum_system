# Logo Test Script for HEM Petroleum
# Run this to check if your logo files exist and are accessible

import os
import sys

def check_logo_files():
    """Check if logo files exist in the static/images directory"""
    
    # Get the directory where this script is located
    base_dir = os.path.dirname(os.path.abspath(__file__))
    images_dir = os.path.join(base_dir, 'static', 'images')
    
    print("HEM Petroleum Logo Check")
    print("=" * 40)
    print(f"Checking directory: {images_dir}")
    print()
    
    # Check if static/images directory exists
    if not os.path.exists(images_dir):
        print("❌ ERROR: static/images directory does not exist!")
        print("Please create the directory and place your logo files there.")
        return False
    
    # List of logo file formats to check
    logo_formats = ['logo.png', 'logo.jpg', 'logo.jpeg', 'logo.svg', 'logo.gif']
    found_logos = []
    
    # Check for logo files
    for logo_file in logo_formats:
        logo_path = os.path.join(images_dir, logo_file)
        if os.path.exists(logo_path):
            file_size = os.path.getsize(logo_path)
            print(f"✅ Found: {logo_file} (Size: {file_size} bytes)")
            found_logos.append(logo_file)
        else:
            print(f"❌ Missing: {logo_file}")
    
    print()
    
    if found_logos:
        print(f"✅ SUCCESS: Found {len(found_logos)} logo file(s)")
        print("Your logo should now display in the application!")
        return True
    else:
        print("❌ ERROR: No logo files found!")
        print("\nTo fix this:")
        print("1. Make sure you have a logo file")
        print("2. Rename it to 'logo.png' (or .jpg, .svg, .gif)")
        print(f"3. Place it in: {images_dir}")
        return False

def list_all_files_in_images():
    """List all files in the images directory"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    images_dir = os.path.join(base_dir, 'static', 'images')
    
    if os.path.exists(images_dir):
        print("\nAll files in static/images directory:")
        print("-" * 40)
        for file in os.listdir(images_dir):
            if os.path.isfile(os.path.join(images_dir, file)):
                print(f"📄 {file}")
    else:
        print("\nstatic/images directory does not exist")

if __name__ == "__main__":
    success = check_logo_files()
    list_all_files_in_images()
    
    print("\n" + "=" * 40)
    if success:
        print("✅ Logo check PASSED - Your logo should display!")
    else:
        print("❌ Logo check FAILED - Please fix the issues above")
    
    input("\nPress Enter to continue...")
