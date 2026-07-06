import { useState } from 'react'
import './App.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5002';

function App() {
  const [activeTab, setActiveTab] = useState('text')
  const [loading, setLoading] = useState(false)
  
  // Text State
  const [textInput, setTextInput] = useState('')
  const [textOutput, setTextOutput] = useState('')
  
  // File State
  const [selectedFile, setSelectedFile] = useState(null)
  const [resultImage, setResultImage] = useState(null)
  const [pdfReady, setPdfReady] = useState(false)

  const handleTextMask = async () => {
    if (!textInput) return;
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('text', textInput);
      
      const response = await fetch(`${API_URL}/mask/text`, {
        method: 'POST',
        body: formData,
      });
      const data = await response.json();
      setTextOutput(data.masked_text);
    } catch (err) {
      console.error(err);
      setTextOutput('Error connecting to the masking server.');
    } finally {
      setLoading(false);
    }
  }

  const handleFileMask = async (type) => {
    if (!selectedFile) return;
    setLoading(true);
    setResultImage(null);
    setPdfReady(false);
    
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      
      const endpoint = type === 'image' ? '/mask/image' : '/mask/pdf';
      
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) throw new Error('Server error');
      
      const blob = await response.blob();
      
      if (type === 'image') {
        const imageUrl = URL.createObjectURL(blob);
        setResultImage(imageUrl);
      } else if (type === 'pdf') {
        const pdfUrl = URL.createObjectURL(blob);
        setPdfReady(pdfUrl);
      }
      
    } catch (err) {
      console.error(err);
      alert('Failed to process the file.');
    } finally {
      setLoading(false);
    }
  }

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setResultImage(null);
      setPdfReady(false);
    }
  }

  return (
    <div className="app-container">
      <div className="glass-panel">
        <header>
          <h1>Shield</h1>
          <p className="subtitle">Enterprise PII Data Masking Gateway</p>
        </header>

        <div className="tabs">
          <button 
            className={`tab-btn ${activeTab === 'text' ? 'active' : ''}`}
            onClick={() => setActiveTab('text')}
          >
            Text
          </button>
          <button 
            className={`tab-btn ${activeTab === 'image' ? 'active' : ''}`}
            onClick={() => setActiveTab('image')}
          >
            Image
          </button>
          <button 
            className={`tab-btn ${activeTab === 'pdf' ? 'active' : ''}`}
            onClick={() => setActiveTab('pdf')}
          >
            PDF Document
          </button>
        </div>

        <div className="workspace">
          {activeTab === 'text' && (
            <>
              <textarea 
                placeholder="Paste sensitive text here..."
                value={textInput}
                onChange={(e) => setTextInput(e.target.value)}
              />
              <button 
                className="primary-btn"
                onClick={handleTextMask}
                disabled={loading || !textInput}
              >
                {loading ? <><span className="loader"></span> Masking...</> : 'Mask Text'}
              </button>
              
              {textOutput && (
                <div className="result-box">
                  <h3>Sanitized Result:</h3>
                  <p style={{ whiteSpace: 'pre-wrap', lineHeight: '1.6' }}>{textOutput}</p>
                </div>
              )}
            </>
          )}

          {activeTab === 'image' && (
            <>
              <label className={`file-dropzone ${selectedFile ? 'has-file' : ''}`}>
                <input 
                  type="file" 
                  accept="image/*"
                  onChange={handleFileChange} 
                  style={{ display: 'none' }} 
                />
                <p>{selectedFile ? selectedFile.name : 'Drag & drop an image or click to select'}</p>
              </label>
              
              <button 
                className="primary-btn"
                onClick={() => handleFileMask('image')}
                disabled={loading || !selectedFile}
              >
                {loading ? <><span className="loader"></span> Scanning OCR...</> : 'Mask Image'}
              </button>

              {resultImage && (
                <div className="result-box">
                  <h3>Sanitized Image:</h3>
                  <img src={resultImage} alt="Masked Result" className="preview-image" />
                </div>
              )}
            </>
          )}

          {activeTab === 'pdf' && (
            <>
              <label className={`file-dropzone ${selectedFile ? 'has-file' : ''}`}>
                <input 
                  type="file" 
                  accept="application/pdf"
                  onChange={handleFileChange} 
                  style={{ display: 'none' }} 
                />
                <p>{selectedFile ? selectedFile.name : 'Drag & drop a PDF or click to select'}</p>
              </label>
              
              <button 
                className="primary-btn"
                onClick={() => handleFileMask('pdf')}
                disabled={loading || !selectedFile}
              >
                {loading ? <><span className="loader"></span> Processing Pages...</> : 'Mask PDF'}
              </button>

              {pdfReady && (
                <div className="result-box">
                  <h3>Sanitization Complete!</h3>
                  <a href={pdfReady} download={`masked_${selectedFile.name}`} className="primary-btn" style={{ display: 'inline-block', marginTop: '1rem', textDecoration: 'none' }}>
                    Download Secure PDF
                  </a>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
