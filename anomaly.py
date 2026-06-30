from mongo import login_signals
import numpy as np
from sklearn.ensemble import IsolationForest

def extract_features (signal, ip, device_signature):
    timestamp = signal["timestamp"]
    hour = timestamp.hour
    day_of_week = timestamp.weekday()
    ip_changed = signal["ip_address"] != ip
    device_changed = signal["user_agent"] != device_signature
    return [hour, day_of_week, ip_changed, device_changed]

def analyze_login (email):
    all_signals = list(login_signals.find({"email":email}).sort("timestamp",1))
    if len(all_signals)<15:
        return {"verdict":"insufficient_data","message":"need at least 15 logins to analyze"}
    feature_matrix = []
    for i, signal in enumerate(all_signals):
        if i == 0:
            continue
        prev_ip = all_signals[i-1]["ip_address"]
        prev_device = all_signals[i-1]["user_agent"]
        features = extract_features(signal, prev_ip, prev_device)
        feature_matrix.append(features)
    X  = np.array(feature_matrix)
    model = IsolationForest(contamination = -1, random_state = 42)
    model.fit(X)
    latest_signal = all_signals[-1]
    prev_ip = all_signals[-2]["ip_address"]
    prev_device = all_signals[-2]["user_agent"]
    latest_features = np.array([extract_features(latest_signal, prev_ip, prev_device)])
    prediction = model.predict(latest_features)[0]
    score = model.score_samples(latest_features)[0]

    if prediction == -1:
        return {"verdict":"anomaly", "score":score}
    else:
        return{"verdict":"normal", "score":score}
    
    



