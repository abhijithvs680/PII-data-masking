import io
import re
import cv2
import fitz  # PyMuPDF
import numpy as np
import pytesseract
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from gliner import GLiNER

app = FastAPI(title="GLiNER On-Premises PII Masking Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    "SOCIAL_HANDLE": re.compile(r'@\w{1,15}\b'),
    "DATE": re.compile(r'\b\d{1,2}[-/\s]?(?:[a-zA-Z]{3,9}|\d{1,2})[-/\s]?\d{2,4}\b')
}

# --- PROCESS ENGINE HELPERS ---

def get_entities_with_chunking(text: str, threshold: float = 0.42) -> list:
    """Chunks text, predicts entities with GLiNER, and remaps indices to original text."""
    max_chars = 1500
    overlap = 250
    start = 0
    text_len = len(text)
    
    all_entities = []
    # To handle overlaps, we track seen entities by their exact span (start, end, label)
    seen_spans = set()
    
    while start < text_len:
        end = start + max_chars
        if end >= text_len:
            chunk = text[start:text_len]
            actual_end = text_len
        else:
            space_idx = text.rfind(' ', start, end)
            if space_idx != -1 and space_idx > start + overlap:
                actual_end = space_idx
            else:
                actual_end = end
            chunk = text[start:actual_end]
            
        chunk_ents = model.predict_entities(chunk, GLINER_LABELS, threshold=threshold)
        
        for ent in chunk_ents:
            global_start = start + ent["start"]
            global_end = start + ent["end"]
            
            span_key = (global_start, global_end, ent["label"])
            if span_key not in seen_spans:
                seen_spans.add(span_key)
                all_entities.append({
                    "start": global_start,
                    "end": global_end,
                    "label": ent["label"],
                    "text": ent["text"]
                })
                
        if actual_end >= text_len:
            break
            
        start = actual_end - overlap
        next_space = text.find(' ', start)
        if next_space != -1 and next_space < actual_end:
            start = next_space + 1
            
    return all_entities

def hybrid_mask_text(text: str) -> str:
    """Processes text using the hybrid regex and grouped GLiNER pipeline."""
    if not text.strip():
        return text
        
    # Phase 1: Clear structural tokens via regex first
    masked_text = text
    for label, pattern in REGEX_PATTERNS.items():
        masked_text = pattern.sub(f"<{label}>", masked_text)
        
    # Phase 2: Analyze remaining contextual metadata
    entities = get_entities_with_chunking(masked_text, threshold=0.42)
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
        
    # Preprocessing to handle watermarks
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
    data = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT)
    
    text_lines = []
    current_line = []
    current_line_num = -1
    word_boxes = []
    
    for i in range(len(data['text'])):
        word = data['text'][i].strip()
        if word:
            uid = f"{data['block_num'][i]}_{data['par_num'][i]}_{data['line_num'][i]}"
            
            if current_line_num != uid:
                if current_line:
                    text_lines.append(" ".join(current_line))
                current_line = []
                current_line_num = uid
                
            current_line.append(word)
            word_boxes.append({
                "word": word,
                "x": data['left'][i],
                "y": data['top'][i],
                "w": data['width'][i],
                "h": data['height'][i]
            })
            
    if current_line:
        text_lines.append(" ".join(current_line))
        
    full_ocr_text = "\n".join(text_lines)
    if not full_ocr_text.strip():
        return image_bytes
        
    strings_to_mask = set()
    
    # 1. Regex matches on the full reconstructed layout
    for pattern in REGEX_PATTERNS.values():
        for match in pattern.findall(full_ocr_text):
            strings_to_mask.add(match)
            
    # 2. GLiNER context matches
    entities = get_entities_with_chunking(full_ocr_text, threshold=0.35)
    for ent in entities:
        strings_to_mask.add(ent["text"])
        
    # 3. Apply blackout blocks by matching discovered strings back to pixel coordinates
    for text_to_hide in strings_to_mask:
        for segment in text_to_hide.split():
            if len(segment) < 2:
                continue
            for box in word_boxes:
                if segment.lower() in box["word"].lower():
                    x, y, w, h = box["x"], box["y"], box["w"], box["h"]
                    cv2.rectangle(img, (x - 2, y - 2), (x + w + 4, y + h + 4), (0, 0, 0), -1)
                    
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
    """
    Optimized PDF Endpoint:
    Iterates through native text words via search mapping and screens 
    embedded rasters efficiently to prevent CPU/RAM lockups.
    """
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Please upload a valid PDF file.")
        
    pdf_bytes = await file.read()
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    
    for page in doc:
        # --- PHASE 1: NATIVE TEXT LAYER MASKING ---
        words = page.get_text("words")
        if words:
            full_text = ""
            word_boxes = []
            current_line = -1
            
            for w in words:
                x0, y0, x1, y1, word, block_num, line_num, word_num = w
                uid = f"{block_num}_{line_num}"
                
                if current_line != uid:
                    if current_line != -1:
                        full_text += "\n"
                    current_line = uid
                else:
                    full_text += " "
                    
                start_idx = len(full_text)
                full_text += word
                end_idx = len(full_text)
                
                word_boxes.append({
                    "x0": x0, "y0": y0, "x1": x1, "y1": y1,
                    "start": start_idx,
                    "end": end_idx
                })
            
            strings_to_mask = set()
            
            # 1. Regex matches on full reconstructed string
            for label, pattern in REGEX_PATTERNS.items():
                for m in pattern.finditer(full_text):
                    strings_to_mask.add((m.start(), m.end()))
                    
            # 2. GLiNER matches
            entities = get_entities_with_chunking(full_text, threshold=0.45)
            for ent in entities:
                # Guardrail: Ignore purely numeric entities (like "760" or "4.5")
                text_str = ent["text"].strip().replace('.', '').replace(',', '')
                if text_str.isdigit():
                    continue
                strings_to_mask.add((ent["start"], ent["end"]))
                
            # 3. Apply exact blackout boxes
            for start_idx, end_idx in strings_to_mask:
                for box in word_boxes:
                    # Check if the word box falls within the masked interval (overlap)
                    if box["start"] < end_idx and box["end"] > start_idx:
                        rect = fitz.Rect(box["x0"] - 2, box["y0"] - 2, box["x1"] + 2, box["y1"] + 2)
                        page.add_redact_annot(rect, fill=(0, 0, 0)) # Clean black box mask

        # Apply text masks natively to the layout page canvas surface
        page.apply_redactions()
        
        # --- PHASE 2: OPTIMIZED EMBEDDED IMAGE PROCESSING ---
        image_list = page.get_images(full=True)
        for img_info in image_list:
            xref = img_info[0]  # Crucial Fix: extract raw integer ID from metadata tuple
            base_image = doc.extract_image(xref)
            if not base_image:
                continue
                
            # PERFORMANCE FILTER: Skip processing tiny shapes, lines, icons, or background vectors
            if base_image["width"] < 50 or base_image["height"] < 50:
                continue
                
            raw_image_bytes = base_image["image"]
            
            # Only send valid images to the local OCR processor
            sanitized_img_bytes = ocr_and_mask_image(raw_image_bytes)
            page.replace_image(xref, stream=sanitized_img_bytes)
            
    # Compile the final document output directly into memory buffer bytes
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
