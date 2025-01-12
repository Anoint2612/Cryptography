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

def preprocess_url(url):
    features = []
    parsed = urlparse(url)
    
   
    features.append(len(urlparse(url).netloc))  # hostname_length
    features.append(len(urlparse(url).path))    # path_length
    
   
    try:
        features.append(len(urlparse(url).path.split('/')[1]))  # fd_length
    except:
        features.append(0)
    
    
    features.append(url.count('-'))   
    features.append(url.count('@'))  
    features.append(url.count('?'))   
    features.append(url.count('%'))   
    features.append(url.count('.'))   
    features.append(url.count('='))   
    features.append(url.count('http'))  
    features.append(url.count('https')) 
    features.append(url.count('www'))  
    
    
    features.append(sum(c.isdigit() for c in url))  
    
    
    ip_pattern = re.compile(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}'
    )
    features.append(1 if not ip_pattern.search(url) else -1)  

    return np.array(features).reshape(1, -1)

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        processed_url = preprocess_url(url)
        prediction = model.predict(processed_url)
        
        is_malicious = bool(prediction[0][0] > 0.5)
        confidence = float(prediction[0][0])
        
        return jsonify({
            'url': url,
            'is_malicious': is_malicious,
            'confidence': confidence
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
