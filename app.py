from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
import numpy as np
from urllib.parse import urlparse
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)

# Load the trained model
model = load_model('Malicious_URL_Prediction.h5')

# Function to preprocess the URL for feature extraction
def preprocess_url(url):
    features = []
    parsed = urlparse(url)

    # Extract various features from the URL
    features.append(len(parsed.netloc))  # hostname_length
    features.append(len(parsed.path))    # path_length

    try:
        features.append(len(parsed.path.split('/')[1]))  # fd_length
    except:
        features.append(0)

    features.append(url.count('-'))   
    features.append(url.count('@'))  
    features.append(url.count('?'))   
    features.append(url.count('%'))   
    features.append(url.count('.'))   
    features.append(url.count('='))   

    # Add more features if needed

    return np.array(features).reshape(1, -1)

# Function to detect XSS attacks in URLs
def detect_xss(url):
    xss_patterns = [
        r'<script.*?>.*?</script>',  # Basic script tags
        r'javascript:',             # Inline JavaScript
        r'onmouseover',              # JavaScript event handlers
        r'onerror',                  # JavaScript error handlers
    ]
    for pattern in xss_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = preprocess_url(url)

    # Predict whether the URL is malicious
    prediction = model.predict(features)

    # Convert prediction to a more readable format
    is_malicious = prediction[0] > 0.5
    return jsonify({
        'url': url,
        'is_malicious': is_malicious
    })

@app.route('/api/xss-detect', methods=['POST'])
def xss_detect():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Check if the URL contains XSS patterns
    is_xss = detect_xss(url)
    return jsonify({
        'url': url,
        'is_xss': is_xss
    })

if __name__ == '__main__':
    app.run(debug=True)
