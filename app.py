import streamlit as st
import cv2
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode
import fitz
import io

# --- Logic Modules ---

def get_safety_rating(url):
    """
    Evaluates URL safety.
    Replace the internal lists with an API call (e.g., VirusTotal) for real-world use.
    """
    # Simulated Fraud/Safe Lists
    malicious_keywords = ["nuevo-core.com", "phish", "scam", "bit.ly/malicious"]
    safe_domains = ["google.com", "microsoft.com", "github.com", "wikipedia.org"]
    
    if any(site in url for site in malicious_keywords):
        return 1, "CRITICAL: Potential Fraud/Spam Link Detected!"
    elif any(site in url for site in safe_domains):
        return 5, "SAFE: Verified Trusted Domain."
    else:
        return 3, "CAUTION: Unverified URL. Analyze before proceeding."

def get_metadata(uploaded_file):
    # Reset file pointer to beginning for processing
    uploaded_file.seek(0)
    file_type = uploaded_file.type
    if "image" in file_type:
        img = Image.open(uploaded_file)
        return {"Format": img.format, "Size": img.size, "Mode": img.mode}
    elif "pdf" in file_type:
        doc = fitz.open(stream=uploaded_file.read(), filetype="pdf")
        return doc.metadata
    return {"Error": "Unsupported file format."}

def analyze_qr(uploaded_file):
    uploaded_file.seek(0)
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    img = cv2.imdecode(file_bytes, 1)
    decoded_objects = decode(img)
    return decoded_objects[0].data.decode('utf-8') if decoded_objects else None

# --- Streamlit UI ---

st.set_page_config(page_title="Security Analysis Toolkit", layout="centered")
st.title("🛡️ Security Analysis Toolkit")
option = st.sidebar.selectbox("Choose Tool", ["QR Code Fraud Detection", "Metadata Extractor"])

if option == "QR Code Fraud Detection":
    st.header("QR Code Scanner")
    qr_file = st.file_uploader("Upload QR Code", type=['png', 'jpg', 'jpeg'])
    
    if qr_file:
        data = analyze_qr(qr_file)
        if data:
            if data.startswith("http"):
                rating, msg = get_safety_rating(data)
                
                # Logic for visual feedback
                if rating == 1:
                    bg_color = "#FF4B4B" # Red
                elif rating == 3:
                    bg_color = "#FFA500" # Orange
                else:
                    bg_color = "#00CC96" # Green
                
                st.markdown(f"""
                <div style="background-color: {bg_color}; padding: 15px; border-radius: 10px; color: white;">
                    <h4 style="color: white;">Scan Result:</h4>
                    <p><strong>Content:</strong> {data}</p>
                    <p><strong>Safety Rating:</strong> {rating}/5</p>
                    <p><strong>Status:</strong> {msg}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info(f"Detected Text: {data}")
        else:
            st.error("No QR Code detected in the image.")

elif option == "Metadata Extractor":
    st.header("Metadata Extraction Utility")
    meta_file = st.file_uploader("Upload Image or PDF", type=['png', 'jpg', 'jpeg', 'pdf'])
    if meta_file:
        data = get_metadata(meta_file)
        st.json(data)