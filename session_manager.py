import uuid
from session import sessions
from datetime import datetime

def start_session(email):
    session_id = str(uuid.uuid4())
    session_start = datetime.utcnow()
    session_doc = {
        "session_id":session_id,
        "session_start":session_start,
        "session_end" : None,
        "email": email,
        "requests":[]
    }
    sessions.insert_one(session_doc)
    return session_id

def log_request(session_id, endpoint):
    request_entry = {"endpoint":endpoint,
                     "timestamp":datetime.utcnow()}
    sessions.update_one(
        {"session_id":session_id},
        {"$push":{"requests":request_entry}}
    )

def end_session(session_id):
    sessions.update_one(
        {"session_id":session_id},
        {"$set":{"session_end":datetime.utcnow()}}
    )
    


