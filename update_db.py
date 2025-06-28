#!/usr/bin/env python3
"""
Simple script to update the database schema for the petroleum management system.
Run this after updating the code to apply database migrations.
"""

import sys
import os
import sqlite3

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hem_petroleum import create_tables, DB_PATH

def sync_suppliers():
    """
    Synchronize suppliers from inventory to the suppliers table
    """
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get distinct suppliers from inventory
        cursor.execute("SELECT DISTINCT supplier FROM inventory WHERE supplier IS NOT NULL AND supplier != ''")
        inventory_suppliers = [row['supplier'] for row in cursor.fetchall()]
        
        # Get existing suppliers
        cursor.execute("SELECT name FROM suppliers")
        existing_suppliers = [row['name'] for row in cursor.fetchall()]
        
        # Find suppliers to add
        suppliers_to_add = [s for s in inventory_suppliers if s not in existing_suppliers]
        
        # Add new suppliers
        for supplier_name in suppliers_to_add:
            cursor.execute("INSERT INTO suppliers (name) VALUES (?)", (supplier_name,))
            print(f"Added supplier: {supplier_name}")
        
        # Commit changes
        conn.commit()
        conn.close()
        
        return len(suppliers_to_add)
    except Exception as e:
        print(f"Error syncing suppliers: {e}")
        return 0

if __name__ == "__main__":
    print("Updating database schema...")
    try:
        create_tables()
        print("Database schema updated successfully!")
        
        # Synchronize suppliers
        added_suppliers = sync_suppliers()
        
        print("\nChanges applied:")
        print("- Added vehicle_reg column to customers table")
        print("- Added product_id column to pumps table")
        print("- Created RTT operations table if not exists")
        print(f"- Synchronized suppliers: {added_suppliers} new suppliers added to suppliers table")
        print("\nYou can now run the application normally.")
    except Exception as e:
        print(f"Error updating database: {e}")
        sys.exit(1)
