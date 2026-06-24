from datetime import datetime, timedelta

def check_lockout(user) -> bool:
    if user.locked_until is not None and datetime.utcnow() < user.locked_until:
        return True
    else:
        return False
    
def update_lockout(user, db):
    user.block_count +=1
    if user.block_count >= 5:
        duration_minutes = 30*(2**(user.block_count - 5))
        user.locked_until = datetime.utcnow() + timedelta(minutes = duration_minutes)
    db.commit()
