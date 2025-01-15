document.addEventListener('DOMContentLoaded', function() {
  initializeEventListeners();
  console.log('Popup initialized');
});

function initializeEventListeners() {
    const urlDetectionCard = document.getElementById('urlDetectionCard');
    if (urlDetectionCard) {
        urlDetectionCard.addEventListener('click', () => {
            document.getElementById('xssDetection').classList.add('hidden');
            document.getElementById('urlDetection').classList.remove('hidden');
            console.log('URL Detection card clicked');
        });
    }

    const xssDetectionCard = document.getElementById('xssDetectionCard');
    if (xssDetectionCard) {
        xssDetectionCard.addEventListener('click', () => {
            document.getElementById('urlDetection').classList.add('hidden');
            document.getElementById('xssDetection').classList.remove('hidden');
            console.log('XSS Detection card clicked');
        });
    }


    const analyzeCurrentButton = document.getElementById('analyzeCurrentButton');
    if (analyzeCurrentButton) {
        analyzeCurrentButton.addEventListener('click', analyzeCurrentUrl);
        console.log('Current URL button listener added');
    }

    const analyzeUrlButton = document.getElementById('analyzeUrlButton');
    if (analyzeUrlButton) {
        analyzeUrlButton.addEventListener('click', analyzeUrl);
        console.log('URL button listener added');
    }
  

    const analyzeXssButton = document.getElementById('analyzeXssButton');
    if (analyzeXssButton) {
        analyzeXssButton.addEventListener('click', analyzeXss);
        console.log('XSS button listener added');
    }
}

// Get current tab URL
async function getCurrentTabUrl() {
  try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      console.log('Current URL retrieved:', tabs[0].url);
      return tabs[0].url;
  } catch (error) {
      console.error('Error getting current URL:', error);
      throw error;
  }
}

// Analyze current page URL
async function analyzeCurrentUrl() {
  try {
      const url = await getCurrentTabUrl();
      const urlInput = document.getElementById('urlInput');
      if (urlInput) {
          urlInput.value = url;
          analyzeUrl();
      }
  } catch (error) {
      console.error('Error in analyzeCurrentUrl:', error);
      showError('Failed to get current URL');
  }
}

async function analyzeUrl() {
  const urlInput = document.getElementById('urlInput');
  const resultsDiv = document.getElementById('results');
  const resultContent = document.getElementById('resultContent');
  const loading = document.getElementById('loading');

  if (!urlInput || !urlInput.value) {
      alert('Please enter a URL');
      return;
  }

  try {
      console.log('Analyzing URL:', urlInput.value);
      loading.classList.remove('hidden');
      resultsDiv.classList.add('hidden');

      const response = await fetch('http://localhost:5000/api/predict', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url: urlInput.value })
      });

      const data = await response.json();
      console.log('Response received:', data);

      if (response.ok) {
          
          const resultHtml = `
              <div class="space-y-3">
                  <div class="flex items-center ${data.is_malicious ? 'text-red-600' : 'text-green-600'}">
                      <i class="fas ${data.is_malicious ? 'fa-exclamation-triangle' : 'fa-check-circle'} text-xl mr-2"></i>
                      <span class="font-semibold text-sm">
                          ${data.is_malicious ? 'Potential Security Risk' : 'URL Appears Safe'}
                      </span>
                  </div>
                  <div class="bg-gray-100 p-3 rounded text-sm">
                      <p class="text-gray-700 truncate"><strong>URL:</strong> ${data.url}</p>
                  </div>
                  <p class="text-xs text-gray-600">
                      ${data.is_malicious 
                          ? 'Warning: This URL shows characteristics commonly associated with malicious websites.'
                          : 'While this URL appears safe, always exercise caution when visiting unknown websites.'}
                  </p>
              </div>
          `;
          
          resultContent.innerHTML = resultHtml;
          resultsDiv.classList.remove('hidden');
      } else {
          throw new Error(data.error || 'Analysis failed');
      }
  } catch (error) {
      console.error('Error in analyzeUrl:', error);
      showError(error.message);
  } finally {
      loading.classList.add('hidden');
  }
}
async function analyzeXss() {
    const xssInput = document.getElementById('xssInput');
    const resultsDiv = document.getElementById('xssResults');
    const resultContent = document.getElementById('xssResultContent');
    const loading = document.getElementById('xssLoading');

    if (!xssInput || !xssInput.value) {
        alert('Please enter text to analyze');
        return;
    }

    try {
        console.log('Analyzing text for XSS:', xssInput.value);
        loading.classList.remove('hidden');
        resultsDiv.classList.add('hidden');

        const response = await fetch('http://localhost:5000/api/check-xss', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ text: xssInput.value })
        });

        const data = await response.json();
        console.log('XSS Response received:', data);

        if (response.ok) {
            const resultHtml = `
                <div class="space-y-3">
                    <div class="flex items-center ${data.is_xss ? 'text-red-600' : 'text-green-600'}">
                        <i class="fas ${data.is_xss ? 'fa-exclamation-triangle' : 'fa-check-circle'} text-xl mr-2"></i>
                        <span class="font-semibold text-sm">
                            ${data.is_xss ? 'XSS Vulnerability Detected' : 'No XSS Detected'}
                        </span>
                    </div>
                    <div class="bg-gray-100 p-3 rounded text-sm">
                        <p class="text-gray-700 truncate"><strong>Input:</strong> ${data.text}</p>
                        
                    </div>
                </div>
            `;
            
            resultContent.innerHTML = resultHtml;
            resultsDiv.classList.remove('hidden');
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    } catch (error) {
        console.error('Error in analyzeXss:', error);
        showError(error.message);
    } finally {
        loading.classList.add('hidden');
    }
}
function showError(message) {
  const resultContent = document.getElementById('resultContent');
  const resultsDiv = document.getElementById('results');
  
  resultContent.innerHTML = `
      <div class="text-red-600 text-sm">
          <i class="fas fa-exclamation-circle mr-2"></i>
          Error: ${message}
      </div>
  `;
  resultsDiv.classList.remove('hidden');
}