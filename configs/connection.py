# configs/connection.py
from dotenv import load_dotenv
import os
from pymongo import MongoClient

load_dotenv()

def get_db_connection():
    mongo_uri = os.getenv("mongoURL")
    client = MongoClient(mongo_uri)
    db = client.get_default_database()
    return db