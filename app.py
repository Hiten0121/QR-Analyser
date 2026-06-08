import streamlit as st
import cv2
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import urlparse
import fitz  # PyMuPDF

# --- Logic Modules ---

def get_metadata(uploaded_file):
    """Extracts metadata from Images or PDFs."""
    uploaded_file.seek(0)
    file_type = uploaded_file.type
    if "image" in file_type:
        img = Image.open(uploaded_file)
        return {"Format": img.format, "Size": img.size, "Mode": img.mode}
    elif "pdf" in file_type:
        doc = fitz.open(stream=uploaded_file.read(), filetype="pdf")
        return doc.metadata
    return {"Error": "Unsupported file format."}

def analyze_url_heuristically(url):
    """Analyzes a URL for fraud patterns using heuristic checks."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. Define Trust Lists
    trusted_domains = ["google.com", "gpay.app", "pay.google.com", "assistant.google.com"]
    
    # 2. Check for exact match or legitimate subdomains
    is_trusted = any(domain == td or domain.endswith("." + td) for td in trusted_domains)
    if is_trusted:
        return 5, "SAFE: The domain is verified and trusted."
    
    # 3. Detect "Brand Impersonation"
    if "gpay" in domain or "google" in domain:
        return 1, "CRITICAL: Brand Impersonation detected! Likely a phishing attempt."
    
    # 4. Check for common suspicious signs
    if len(domain) > 20 or "-" in domain:
        return 2, "WARNING: Suspicious URL structure (lengthy or contains hyphens)."
        
    return 3, "CAUTION: Unverified destination. Check URL carefully."

def analyze_qr(uploaded_file):
    """Decodes QR code from image."""
    uploaded_file.seek(0)
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    img = cv2.imdecode(file_bytes, 1)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    decoded_objects = decode(gray)
    return decoded_objects[0].data.decode('utf-8') if decoded_objects else None

# --- UI Layout ---

st.set_page_config(page_title="Security Analysis Toolkit", layout="centered")
st.title("🛡️ Security Analysis Toolkit")

option = st.sidebar.selectbox("Choose Tool", ["QR Code Fraud Detection", "Metadata Extractor"])

if option == "QR Code Fraud Detection":
    st.header("QR Code Scanner")
    qr_file = st.file_uploader("Upload QR Code", type=['png', 'jpg', 'jpeg'])
    
    if qr_file:
        data = analyze_qr(qr_file)
        if data:
            st.success(f"Detected Content: {data}")
            
            if data.startswith("http"):
                rating, msg = analyze_url_heuristically(data)
                
                # Dynamic coloring
                bg_color = "#FF4B4B" if rating <= 2 else ("#FFA500" if rating == 3 else "#00CC96")
                
                st.markdown(f"""
                <div style="background-color: {bg_color}; padding: 15px; border-radius: 10px; color: white;">
                    <strong>Safety Rating:</strong> {rating}/5<br>
                    <strong>Status:</strong> {msg}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info("The QR code contains plain text, not a URL.")
        else:
            st.error("No QR Code detected in the image.")

elif option == "Metadata Extractor":
    st.header("Metadata Extraction Utility")
    meta_file = st.file_uploader("Upload Image or PDF", type=['png', 'jpg', 'jpeg', 'pdf'])
    if meta_file:
        data = get_metadata(meta_file)
        st.json(data)
