# Security Analysis Tools

This project provides a **Malicious URL Detection Tool** that uses a trained machine learning model to predict if a given URL is malicious. It includes a **Flask API** to handle predictions and a **Chrome Extension** for easy access and interaction with the tool.

---

## 📋 Features

- **Malicious URL Prediction**: Analyze URLs for malicious patterns using a pre-trained model.
- **Confidence Score**: Provides a confidence level for the prediction.
- **Chrome Extension Integration**: Enables users to analyze URLs directly from their browser.
- **Interactive UI**: A user-friendly interface built with **HTML**, **CSS**, and **TailwindCSS**.

---

## 💻 Technology Stack
- **Backend**: Flask, Python, TensorFlow, NumPy
- **Frontend**: HTML, CSS, JavaScript (for Chrome extension)
- **Machine Learning**: TensorFlow model for malicious URL prediction

---


## 🛠️ Requirements

To set up and run the project, ensure you have the following installed:

### Python Environment
- **Python**: Version 3.8 or above
- **Pip**: Latest version installed
- **Python Libraries**:
  - `Flask`
  - `Flask-CORS`
  - `tensorflow`
  - `numpy`

### Chrome Extension
- A Chromium-based browser (Google Chrome or Microsoft Edge).

---

## 🚀 Setup and Installation

### Backend (Flask API)
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
   
2.**Navigate to the Backend Folder:** Ensure you're in the folder containing app.py.

3.**Install Dependencies:** Run the following command to install the required Python libraries:
```bash
pip install -r requirements.txt
```
requirements.txt:
```bash
Flask
Flask-CORS
tensorflow
numpy
```

4.**Place the Pre-trained Model:** Ensure the Malicious_URL_Prediction.h5 file is in the same directory as app.py.

5.**Run the Flask Server:**
```bash
python app.py
```


### 🌐 Chrome extension

1.**Navigate to the extensions Folder:** This folder contains the Chrome extension files: popup.html, popup.js, and manifest.json.

2.**Load the Extension in Chrome:**
- Open Chrome and navigate to chrome://extensions.
- Enable **Developer Mode**.
- Click on Load unpacked and select the extensions folder.

3.**Test the Extension:**
- Click the extension icon in the Chrome toolbar.
- Enter or analyze a URL using the provided interface.

---

## 📊 How It Works

### URL Preprocessing (Backend)

### Features Extracted:
- URL length: Overall length of the URL.
- Hostname length: Length of the domain/hostname.
- Path length: Length of the URL path.
- Frequency of special characters (-, @, ?, %, ., =).
- Presence of IP addresses.
- Count of digits in the URL.

**Model Prediction:**
The processed features are passed to the pre-trained model (Malicious_URL_Prediction.h5).

**Outputs:**

- is_malicious: Boolean indicating if the URL is malicious.
- confidence: A floating-point value showing prediction confidence.

---

## 🌟 Key Components
### Backend
- File: app.py
- Technology: Flask
- Endpoints:
    - /api/predict (POST): Accepts a URL and returns prediction results.
### Chrome Extension
- Popup HTML: Provides the UI for the extension.
- Popup JS: Handles API requests and DOM interactions.
- Manifest.json: Configures the extension.

---

## 🖥️ Usage

**Analyze a URL via Flask API:**

- Send a POST request to http://localhost:5000/api/predict with a JSON payload:
```bash
{
  "url": "https://example.com"
}
```
- Example Response:
```bash
{
  "url": "https://example.com",
  "is_malicious": false,
  "confidence": 0.42
}
```
 **Analyze a URL via Chrome Extension:**
 
- Open the Chrome extension popup.
- Enter a URL or analyze the current page.

---

## 📂 File Structure

```bash
├── app.py                   # Flask backend
├── Malicious_URL_Prediction.h5 # Trained ML model
├── requirements.txt         # Python dependencies(This is to be added to install the requirements)
├── extensions               # Chrome extension folder
│   ├── popup.html           # Extension UI
│   ├── popup.js             # Extension logic
│   ├── manifest.json        # Extension configuration
│   └── images               # folder with Extension icons
└── README.md                # Documentation
```

---

## 📖 Future Enhancements
- Add more machine learning models for enhanced detection accuracy.
- Integrate additional security tools into the Chrome extension.
- Allow batch URL analysis via file uploads.

---

## Output
![Screenshot 2025-01-13 000940](https://github.com/user-attachments/assets/ad497638-ae06-42ee-a6f9-5db64eaccd24)
