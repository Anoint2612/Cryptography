from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
import numpy as np
from urllib.parse import urlparse, unquote
from flask_cors import CORS
import re
import nltk as nltk
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
import pickle
import logging
from sklearn import __version__ as sklearn_version
nltk.download('punkt_tab')
nltk.download('punkt')
nltk.download('wordnet')
nltk.download('omw-1.4')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logging.getLogger('gensim').setLevel(logging.WARNING)

app = Flask(__name__)
CORS(app)
def preprocess_url(url):
    features = []
    parsed = urlparse(url)
    features.append(len(urlparse(url).netloc)) 
    features.append(len(urlparse(url).path))    
    try:
        features.append(len(urlparse(url).path.split('/')[1]))  
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

def load_xss_models():
    models = {}
    base_models = {
        'dtc': 'DecisionTreeClassifier.sav',
        'svc': 'SVC.sav',
        'knn': 'KNeighborsClassifier.sav',
        'rfc': 'RandomForestClassifier.sav',
        'mlp': 'MLPClassifier.sav'
    }
    
    logger.info(f"Loading models with sklearn version {sklearn_version}")
    
    for key, filename in base_models.items():
        try:
            with open(filename, 'rb') as f:
                models[key] = pickle.load(f)
            logger.info(f"Successfully loaded {filename}")
        except Exception as e:
            logger.error(f"Failed to load {filename}: {e}")
            models[key] = None
    return models

def getVec(text):
    tagged_data = [TaggedDocument(words=word_tokenize(_d.lower()), tags=[str(i)]) for i, _d in enumerate(text)]
    max_epochs = 10
    vec_size = 20
    alpha = 0.025

    model = Doc2Vec(
        vector_size=20,
        alpha=0.025,
        min_alpha=0.00025,
        min_count=1,
        dm=1,
        workers=3,
        epochs=10,
        callbacks=[]  
    )
    model.build_vocab(tagged_data)
    
    features = []
    for epoch in range(max_epochs):
        model.random.seed(42)
        model.train(tagged_data,
                total_examples=model.corpus_count,
                epochs=model.epochs)
        model.alpha -= 0.0002
        model.min_alpha = model.alpha
    
    for i, line in enumerate(text):
        featureVec = [model.dv[i]]
        lineDecode = unquote(line)
        lineDecode = lineDecode.replace(" ", "")
        lowerStr = str(lineDecode).lower()
        feature1 = sum(lowerStr.count(tag) for tag in [
            '<link', '<object', '<form', '<embed', '<ilayer', '<layer', 
            '<style', '<applet', '<meta', '<img', '<iframe', '<input',
            '<body', '<video', '<button', '<math', '<picture', '<map',
            '<svg', '<div', '<a', '<details', '<frameset', '<table',
            '<comment', '<base', '<image'
        ])

        feature2 = sum(lowerStr.count(event) for event in [
            'exec', 'fromcharcode', 'eval', 'alert', 'getelementsbytagname',
            'write', 'unescape', 'escape', 'prompt', 'onload', 'onclick',
            'onerror', 'onpage', 'confirm', 'marquee'
        ])
        feature3 = lowerStr.count('.js')
        feature4 = lowerStr.count('javascript')
        feature5 = len(lowerStr)
        feature6 = sum(lowerStr.count(script) for script in [
            '<script', '&lt;script', '%3cscript', '%3c%73%63%72%69%70%74'
        ])
        feature7 = sum(lowerStr.count(char) for char in [
            '&', '<', '>', '"', "'", '/', '%', '*', ';', '+', '=', '%3C'
        ])
        feature8 = lowerStr.count('http')
        featureVec = np.append(featureVec, [
            feature1, feature2, feature3, feature4, 
            feature5, feature6, feature7, feature8
        ])
        features.append(featureVec)
    
    return features
    
    return features
try:
    logger.info("Loading models...")
    url_model = load_model('Malicious_URL_Prediction.h5')
    xss_models = load_xss_models()
    
    if all(model is None for model in xss_models.values()):
        raise Exception("No XSS models could be loaded")
        
except Exception as e:
    logger.error(f"Error loading models: {e}")
    raise
@app.route('/api/check-xss', methods=['POST'])
def check_xss():
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    try:
        features = getVec([text])
        predictions = {}
        weights = {
            'dtc': 0.175, 'svc': 0.15, 'gnb': 0.05,
            'knn': 0.075, 'rfc': 0.25, 'mlp': 0.3
        }
        
        for key, model in xss_models.items():
            if model is not None:
                try:
                    pred = model.predict(features)
                    predictions[key] = float(pred[0])
                except Exception as e:
                    logger.error(f"Prediction error with {key}: {str(e)}")
                    
        if not predictions:
            return jsonify({'error': 'No models available for prediction'}), 500
        score = sum(predictions[k] * weights[k] for k in predictions.keys())
        return jsonify({
            'text': text,
            'is_xss': score >= 0.3,  
            'result': 'XSS Detected' if score >= 0.3 else 'Safe',
            'debug_info': {
                'model_predictions': predictions,
                'weighted_score': score
            } if app.debug else None
        })
    
    except Exception as e:
        logger.error(f"XSS check error: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        processed_url = preprocess_url(url)
        prediction = url_model.predict(processed_url)
        
        is_malicious = bool(prediction[0][0] > 0.5)
        confidence = float(prediction[0][0])
        
        return jsonify({
            'url': url,
            'is_malicious': is_malicious,
            'confidence': confidence
        })
    
    except Exception as e:
        logger.error(f"URL prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True,port=5000)