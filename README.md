# GLiNER On-Premises PII Masking Gateway

This is a fast, locally-hosted PII (Personally Identifiable Information) masking gateway built with FastAPI, GLiNER, and Tesseract OCR.

It allows you to safely detect and redact sensitive information such as people's names, emails, phone numbers, credit cards, organizations, and locations without sending any data to external APIs.

## Features
- **Text Masking (`/mask/text`)**: Detects and replaces PII in text strings using the zero-shot GLiNER model.
- **Image Masking (`/mask/image`)**: Extracts text from images via OCR (PyTesseract), analyzes it for PII using GLiNER, and blackouts the exact pixel coordinates on the image.
- **PDF Masking (`/mask/pdf`)**: Scans PDFs for embedded images and redacts sensitive information within them.

## Setup & Installation

You can run the entire application using Docker Compose.

### Requirements
- Docker and Docker Compose

### Running the App
1. Clone this repository.
2. Build and run the containers:
   ```bash
   docker-compose up --build
   ```
3. The API will be available at `http://localhost:8000`. You can view the interactive API documentation at `http://localhost:8000/docs`.
