import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# Load models
rf_model = joblib.load("saved_models/rf_model.pkl")
svm_model = joblib.load("saved_models/svm_model.pkl")
label_encoder = joblib.load("saved_models/label_encoder.pkl")

# Feature extraction functions
def contains_ip_address(url):
    return int(bool(re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])', url)))

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 0 if hostname and re.search(re.escape(hostname), url) else 1

def count_dot(url): return url.count('.')
def count_www(url): return url.count('www')
def count_atrate(url): return url.count('@')
def no_of_dir(url): return urlparse(url).path.count('/')
def no_of_embed(url): return urlparse(url).path.count('//')
def shortening_service(url): return int(bool(re.search(r"(bit\.ly|goo\.gl|shorte\.st|tinyurl\.com|ow\.ly|t\.co)", url)))
def count_https(url): return url.count('https')
def count_http(url): return url.count('http')
def count_per(url): return url.count('%')
def count_ques(url): return url.count('?')
def count_hyphen(url): return url.count('-')
def count_equal(url): return url.count('=')
def url_length(url): return len(url)
def hostname_length(url): return len(urlparse(url).netloc)
def suspicious_words(url): return int(bool(re.search(r"paypal|login|signin|bank|account|update|free|lucky|bonus", url.lower())))
def digit_count(url): return sum(c.isdigit() for c in url)
def letter_count(url): return sum(c.isalpha() for c in url)
def fd_length(url): return len(urlparse(url).path.split('/')[1]) if '/' in urlparse(url).path else 0

def is_sql_injection(url):
    patterns = [
        r"(?i)(\%27)|(')|(\-\-)|(\%23)|(#)",
        r"(?i)(\bOR\b|\bAND\b).*(=|\d|')",
        r"(?i)UNION(\s+ALL)?(\s+SELECT)?",
        r"(?i)SELECT.+FROM",
        r"(?i)INSERT\s+INTO",
        r"(?i)DROP\s+TABLE",
        r"(?i)UPDATE\s+\w+\s+SET",
        r"(?i)(\bEXEC\b|\bEXECUTE\b)",
        r"(?i)(')\s*or\s*\d+\s*=\s*\d+"
    ]
    return int(any(re.search(p, url) for p in patterns))

def is_xss_attack(url):
    patterns = [
        r"(?i)<script.*?>.*?</script>", r"(?i)javascript:", r"(?i)on\w+\s*=",
        r"(?i)document\.", r"(?i)window\.", r"(?i)eval\(", r"(?i)<.*?on\w+=.*?>",
        r"(?i)<iframe", r"(?i)<img.*?src=.*?>"
    ]
    return int(any(re.search(p, url) for p in patterns))

def extract_features(url):
    return [
        contains_ip_address(url), abnormal_url(url), count_dot(url), count_www(url),
        count_atrate(url), no_of_dir(url), no_of_embed(url), shortening_service(url),
        count_https(url), count_http(url), count_per(url), count_ques(url),
        count_hyphen(url), count_equal(url), url_length(url), hostname_length(url),
        suspicious_words(url), fd_length(url), digit_count(url), letter_count(url)
    ]

def predict_url(url):
    features = extract_features(url)
    rf_pred = rf_model.predict([features])[0]
    svm_pred = svm_model.predict([features])[0]
    return {
        "URL": url,
        "Prediction_RF": label_encoder.inverse_transform([rf_pred])[0],
        "Prediction_SVM": label_encoder.inverse_transform([svm_pred])[0],
        "Possible_SQL_Injection": bool(is_sql_injection(url)),
        "Possible_XSS_Attack": bool(is_xss_attack(url))
    }

# Enhanced UI with Streamlit
st.set_page_config(page_title="🔒 URL & Payload Inspector", layout="centered")
st.title("🔒 Malicious URL & Payload Inspector")
st.markdown("""
<style>
    .stApp { background-color: #f5f7fa; }
    .css-1d391kg { border: 2px solid #0078ff; border-radius: 10px; padding: 20px; }
    .stTextInput > div > input { border: 1px solid #0078ff; }
</style>
""", unsafe_allow_html=True)

option = st.sidebar.radio("Choose Input Mode", ["🔗 Single URL", "📁 Upload CSV File"])

if option == "🔗 Single URL":
    url_input = st.text_input("Enter a URL to analyze")
    if st.button("🚀 Analyze URL"):
        if url_input:
            result = predict_url(url_input)
            st.success("✅ Analysis Complete")
            st.json(result)
        else:
            st.warning("⚠️ Please enter a URL")
else:
    uploaded_file = st.file_uploader("Upload a CSV with 'url' column", type="csv")
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        if "url" not in df.columns:
            st.error("❌ CSV must contain a 'url' column")
        else:
            st.info("🔍 Analyzing URLs, please wait...")
            results = df["url"].apply(predict_url)
            result_df = pd.DataFrame(results.tolist())
            st.dataframe(result_df)
            st.download_button("📥 Download Results", result_df.to_csv(index=False), "predicted_urls.csv")
