import io
import cv2
import fitz  # PyMuPDF
import numpy as np
import pytesseract
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from gliner import GLiNER

app = FastAPI(title="GLiNER On-Premises PII Masking Gateway")

# Load the small, highly accurate 200MB GLiNER model locally into memory
print("Loading GLiNER model...")
model = GLiNER.from_pretrained("urchade/gliner_small-v2.1")

# Define the custom PII labels you want GLiNER to actively target
PII_LABELS = ["person", "email", "phone number", "credit card", "organization", "location"]


# --- HELPER FUNCTIONS ---

def gliner_mask_text(text: str) -> str:
    """Uses GLiNER to dynamically find and swap PII entities in a string."""
    if not text.strip():
        return text
    
    # Predict the entities and their exact index spans
    entities = model.predict_entities(text, PII_LABELS, threshold=0.5)
    
    # Sort entities in reverse order by start index to mask strings without breaking text offsets
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    
    masked_text = text
    for ent in sorted_entities:
        start = ent["start"]
        end = ent["end"]
        label = ent["label"].upper()
        # Swap the sensitive data chunk with the semantic token format
        masked_text = masked_text[:start] + f"<{label}>" + masked_text[end:]
        
    return masked_text


def ocr_and_mask_image(image_bytes: bytes) -> bytes:
    """Extracts text coordinates via Tesseract, evaluates words with GLiNER, and blackouts image."""
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    # Use Tesseract to get all words and bounding box structures
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    
    # Group found image texts to pass to GLiNER for contextual intelligence evaluation
    raw_words = [data['text'][i] for i in range(len(data['text'])) if data['text'][i].strip()]
    full_ocr_sentence = " ".join(raw_words)
    
    if not full_ocr_sentence.strip():
        return image_bytes  # No text found in image
        
    # Get entities matching target PII labels from the image sentence context
    entities = model.predict_entities(full_ocr_sentence, PII_LABELS, threshold=0.5)
    
    # Match GLiNER found words back to their pixel coordinates inside the image structure
    for ent in entities:
        text_to_hide = ent["text"]
        # Split multi-word entities (like "John Doe") to capture bounding boxes individually
        for segment in text_to_hide.split():
            for i in range(len(data['text'])):
                if segment.lower() in data['text'][i].lower():
                    x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                    # Paint solid black boxes directly over the target coordinates
                    cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 0), -1)
                    
    _, encoded_img = cv2.imencode('.png', img)
    return encoded_img.tobytes()


# --- ENDPOINTS ---

@app.post("/mask/text")
async def mask_text(text: str = Form(...)):
    """Endpoint 1: Fast AI Text Entity Masker via GLiNER."""
    return {"masked_text": gliner_mask_text(text)}


@app.post("/mask/image")
async def mask_image(file: UploadFile = File(...)):
    """Endpoint 2: Image Input with OCR parsing and local pixel masking."""
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Please upload a valid image.")
    
    img_bytes = await file.read()
    sanitized_bytes = ocr_and_mask_image(img_bytes)
    return StreamingResponse(io.BytesIO(sanitized_bytes), media_type="image/png")


@app.post("/mask/pdf")
async def mask_pdf(file: UploadFile = File(...)):
    """Endpoint 3: PDF text parsing + Deep embedded inline image OCR redaction."""
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Please upload a valid PDF.")
    
    pdf_bytes = await file.read()
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    
    for page in doc:
        # 1. Look for embedded images deep inside the PDF page layouts
        image_list = page.get_images(full=True)
        for img_info in image_list:
            xref = img_info[0] # Fetch unique identifier reference
            base_image = doc.extract_image(xref)
            raw_image_bytes = base_image["image"]
            
            # Send the isolated sub-image to the local OCR + GLiNER routing logic
            sanitized_img_bytes = ocr_and_mask_image(raw_image_bytes)
            
            # Re-insert the newly blanked-out image straight back into the PDF structure
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
