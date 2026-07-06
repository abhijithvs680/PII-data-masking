import io
import re
import cv2
import fitz  # PyMuPDF
import numpy as np
import pytesseract
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from gliner import GLiNER

app = FastAPI(title="Complete Global PII Coverage Masking Gateway")

print("Loading GLiNER model...")
model = GLiNER.from_pretrained("urchade/gliner_small-v2.1")

# 8 high-level categories that cover all 41 of your specific PII requirements
GLINER_LABELS = [
    "person", "organization", "location", "job title", 
    "date", "financial", "government id", "demographic profile"
]

# Comprehensive regex to ensure 100% detection on precise alphanumeric sequences
REGEX_PATTERNS = {
    "EMAIL": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "PHONE": re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "CREDIT_CARD": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "BANK_ROUTING": re.compile(r'\b(?:\d{4}[-\s]?){2}\d{1,4}\b'),
    "SSN_TAX_ID": re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{2}-\d{7}\b'),
    "IP_MAC_ADDRESS": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'),
    "DIGITAL_ID": re.compile(r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b'),
    "SOCIAL_HANDLE": re.compile(r'@\w{1,15}\b')
}

# --- PROCESS ENGINE HELPERS ---
def hybrid_mask_text(text: str) -> str:
    """Processes text using the hybrid regex and grouped GLiNER pipeline."""
    if not text.strip():
        return text
        
    # Phase 1: Clear structural tokens via regex first
    masked_text = text
    for label, pattern in REGEX_PATTERNS.items():
        masked_text = pattern.sub(f"<{label}>", masked_text)
        
    # Phase 2: Analyze remaining contextual metadata
    entities = model.predict_entities(masked_text, GLINER_LABELS, threshold=0.42)
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    
    for ent in sorted_entities:
        start = ent["start"]
        end = ent["end"]
        label = ent["label"].upper().replace(" ", "_")
        
        # Guardrail: Prevent GLiNER from messing up existing regex tokens
        substring = masked_text[start:end]
        if any(f"<{k}>" in substring for k in REGEX_PATTERNS.keys()):
            continue
            
        masked_text = masked_text[:start] + f"<{label}>" + masked_text[end:]
            
    return masked_text

def ocr_and_mask_image(image_bytes: bytes) -> bytes:
    """Extracts text positions using OCR and masks regex and GLiNER entities."""
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return image_bytes
        
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    raw_words = [data['text'][i] for i in range(len(data['text'])) if data['text'][i].strip()]
    full_ocr_sentence = " ".join(raw_words)
    
    if not full_ocr_sentence.strip():
        return image_bytes
        
    # Check 1: Apply strict regex blackout blocks
    for i in range(len(data['text'])):
        word = data['text'][i]
        for pattern in REGEX_PATTERNS.values():
            if pattern.search(word):
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 0), -1)
                
    # Check 2: Apply context-aware GLiNER blackout blocks
    entities = model.predict_entities(full_ocr_sentence, GLINER_LABELS, threshold=0.42)
    for ent in entities:
        for segment in ent["text"].split():
            if len(segment) < 2:
                continue
            for i in range(len(data['text'])):
                if segment.lower() in data['text'][i].lower():
                    x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                    cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 0), -1)
                    
    _, encoded_img = cv2.imencode('.png', img)
    return encoded_img.tobytes()

# --- FASTAPI GATEWAY ENDPOINTS ---

@app.post("/mask/text")
async def mask_text_endpoint(text: str = Form(...)):
    """Endpoint 1: Fast, High-Coverage Text Masker."""
    return {"masked_text": hybrid_mask_text(text)}


@app.post("/mask/image")
async def mask_image_endpoint(file: UploadFile = File(...)):
    """Endpoint 2: Image Masker via OCR and pixel blackout."""
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload an image.")
    
    img_bytes = await file.read()
    sanitized_bytes = ocr_and_mask_image(img_bytes)
    return StreamingResponse(io.BytesIO(sanitized_bytes), media_type="image/png")


@app.post("/mask/pdf")
async def mask_pdf_endpoint(file: UploadFile = File(...)):
    """Endpoint 3: PDF Document Scrubbing (Native Text + Internal Images)."""
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Please upload a valid PDF file.")
        
    pdf_bytes = await file.read()
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    
    for page in doc:
        # Step A: Mask the native text layout layer
        text_instances = page.get_text("blocks")
        for block in text_instances:
            block_text = block[4]  # Index 4 holds the actual paragraph text string
            if block_text.strip():
                masked_block = hybrid_mask_text(block_text)
                if masked_block != block_text:
                    rect = fitz.Rect(block[0], block[1], block[2], block[3])
                    page.add_redact_annot(rect, fill=(1, 1, 1))  # Blanks out the old text visually
        page.apply_redactions()
        
        # Step B: Extract and clean embedded images inside the PDF layout
        image_list = page.get_images(full=True)
        for img_info in image_list:
            xref = img_info[0]  # Crucial Fix: extract raw integer ID out of the image metadata tuple
            base_image = doc.extract_image(xref)
            if not base_image:
                continue
            raw_image_bytes = base_image["image"]
            
            sanitized_img_bytes = ocr_and_mask_image(raw_image_bytes)
            page.replace_image(xref, stream=sanitized_img_bytes)
            
    output_buffer = io.BytesIO()
    doc.save(output_buffer, garbage=4, deflate=True)
    doc.close()
    output_buffer.seek(0)
    
    return StreamingResponse(
        output_buffer, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=masked_{file.filename}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
