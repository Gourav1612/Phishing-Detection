import re
import socket
import ipaddress
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore') # Ignore SSL warnings for phishing sites

def extract_features(url, include_content=True):
    """
    Extracts features from the given URL to match the exact schema of:
    'phishing_URL_Dataset.csv' (54 input features).
    """
    f = {}
    
    # ---------------------------------------------------------
    # 1. URL-Based Features
    # ---------------------------------------------------------
    try:
        parsed = urlparse(url)
    except:
        parsed = urlparse("")

    hostname = parsed.netloc if parsed.netloc else ""
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""
    
    f['URLLength'] = len(url)
    f['Domain'] = hostname
    f['DomainLength'] = len(hostname)
    
    # IsDomainIP
    try:
        ipaddress.ip_address(hostname.split(':')[0])
        f['IsDomainIP'] = 1
    except:
        f['IsDomainIP'] = 0
        
    # TLD
    parts = hostname.split('.')
    f['TLD'] = parts[-1] if len(parts) > 1 else ""
    f['TLDLength'] = len(f['TLD'])

    # These features require external ML models/datasets for accurate extraction
    # So we're approximating or using reasonable defaults for a real-time scanner
    f['URLSimilarityIndex'] = 100.0  # Placeholder 
    f['CharContinuationRate'] = 0.5   # Placeholder
    f['TLDLegitimateProb'] = 0.5      # Placeholder
    f['URLCharProb'] = 0.5            # Placeholder
    
    f['NoOfSubDomain'] = max(0, len(parts) - 2) if len(parts) > 0 else 0
    f['HasObfuscation'] = 1 if '@' in url else 0
    f['NoOfObfuscatedChar'] = url.count('@')
    f['ObfuscationRatio'] = f['NoOfObfuscatedChar'] / len(url) if len(url) > 0 else 0
    
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    
    f['NoOfLettersInURL'] = letters
    f['LetterRatioInURL'] = letters / len(url) if len(url) > 0 else 0
    f['NoOfDegitsInURL'] = digits
    f['DegitRatioInURL'] = digits / len(url) if len(url) > 0 else 0
    
    f['NoOfEqualsInURL'] = url.count('=')
    f['NoOfQMarkInURL'] = url.count('?')
    f['NoOfAmpersandInURL'] = url.count('&')
    
    special_chars = sum(not c.isalnum() for c in url)
    f['NoOfOtherSpecialCharsInURL'] = special_chars - (f['NoOfEqualsInURL'] + f['NoOfQMarkInURL'] + f['NoOfAmpersandInURL'])
    f['SpacialCharRatioInURL'] = special_chars / len(url) if len(url) > 0 else 0
    
    f['IsHTTPS'] = 1 if parsed.scheme == 'https' else 0

    # ---------------------------------------------------------
    # 2. Content-Based Features
    # ---------------------------------------------------------
    # Initialize defaults
    f['LineOfCode'] = 0
    f['LargestLineLength'] = 0
    f['HasTitle'] = 0
    f['Title'] = ""
    f['DomainTitleMatchScore'] = 0.0
    f['URLTitleMatchScore'] = 0.0
    f['HasFavicon'] = 0
    f['Robots'] = 0
    f['IsResponsive'] = 0
    f['NoOfURLRedirect'] = 0
    f['NoOfSelfRedirect'] = 0
    f['HasDescription'] = 0
    f['NoOfPopup'] = 0
    f['NoOfiFrame'] = 0
    f['HasExternalFormSubmit'] = 0
    f['HasSocialNet'] = 0
    f['HasSubmitButton'] = 0
    f['HasHiddenFields'] = 0
    f['HasPasswordField'] = 0
    f['Bank'] = 0
    f['Pay'] = 0
    f['Crypto'] = 0
    f['HasCopyrightInfo'] = 0
    f['NoOfImage'] = 0
    f['NoOfCSS'] = 0
    f['NoOfJS'] = 0
    f['NoOfSelfRef'] = 0
    f['NoOfEmptyRef'] = 0
    f['NoOfExternalRef'] = 0
    
    if include_content:
        try:
            response = requests.get(url, timeout=0.5, verify=False, allow_redirects=True)
            text = response.text
            soup = BeautifulSoup(text, 'html.parser')
            
            lines = text.splitlines()
            f['LineOfCode'] = len(lines)
            f['LargestLineLength'] = max(len(line) for line in lines) if lines else 0
            
            if soup.title and soup.title.string:
                f['HasTitle'] = 1
                f['Title'] = soup.title.string.strip()
                if hostname.lower() in f['Title'].lower():
                    f['DomainTitleMatchScore'] = 100.0
                    
            f['HasFavicon'] = 1 if soup.find('link', rel=re.compile('^(shortcut )?icon$', re.I)) else 0
            f['HasDescription'] = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
            
            f['NoOfURLRedirect'] = len(response.history)
            
            if soup.find_all('iframe'): f['NoOfiFrame'] = 1
            if 'window.open' in text: f['NoOfPopup'] = 1
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action and not action.startswith('/') and hostname not in action:
                    f['HasExternalFormSubmit'] = 1
                if form.find('input', type='password'):
                    f['HasPasswordField'] = 1
                if form.find('input', type='hidden'):
                    f['HasHiddenFields'] = 1
                if form.find(['input', 'button'], type='submit'):
                    f['HasSubmitButton'] = 1
                    
            text_lower = text.lower()
            f['Bank'] = 1 if 'bank' in text_lower else 0
            f['Pay'] = 1 if 'pay' in text_lower else 0
            f['Crypto'] = 1 if 'crypto' in text_lower or 'bitcoin' in text_lower else 0
            f['HasCopyrightInfo'] = 1 if 'copyright' in text_lower or '©' in text else 0
            
            f['NoOfImage'] = len(soup.find_all('img'))
            f['NoOfCSS'] = len(soup.find_all('link', rel='stylesheet'))
            f['NoOfJS'] = len(soup.find_all('script'))
            
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if href == '#' or href.startswith('javascript:'):
                    f['NoOfEmptyRef'] += 1
                elif href.startswith('/') or hostname in href:
                    f['NoOfSelfRef'] += 1
                else:
                    f['NoOfExternalRef'] += 1
                    
            # Basic social net check
            socials = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
            f['HasSocialNet'] = 1 if any(s in text_lower for s in socials) else 0

        except Exception as e:
            # If site is unreachable, return mostly 0s
            pass
            
    # Remove string features before returning to match ML model input (which expects numbers)
    if 'Domain' in f: del f['Domain']
    if 'TLD' in f: del f['TLD']
    if 'Title' in f: del f['Title']
        
    return f
