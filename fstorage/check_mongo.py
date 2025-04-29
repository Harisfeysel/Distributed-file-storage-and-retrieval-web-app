from pymongo import MongoClient

try:
    # Connect to MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    
    # Check available databases
    print("Available databases:", client.list_database_names())
    
    # Try to access file_storage_app database
    db = client['file_storage_app']
    
    # Count documents in files collection with folder_id: root
    count = db.files.count_documents({'folder_id': 'root'})
    print(f"Number of files with folder_id 'root': {count}")
    
    # List all collections in the database
    print("Collections in file_storage_app:", db.list_collection_names())
    
except Exception as e:
    print(f"Error: {e}") 