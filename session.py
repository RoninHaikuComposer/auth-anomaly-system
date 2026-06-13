from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017")
db = client["auth_anomaly_db"]
sessions = db["sessions"]
