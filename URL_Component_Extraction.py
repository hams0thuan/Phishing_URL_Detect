import re
import numpy as np
from tld import get_tld, is_tld
from urllib.parse import urlparse
import whois
import tldextract
import requests

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                        r"tr\.im|link\.zip\.net"  


def having_IP(url):
        match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
                '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
                '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6split_url = split_url
        if match :
                return 1
        else: 
                return 0 

    # Check top-level domain if valid or not

def check_tld(url):
        try:
    #       Extract the top level domain (TLD) 
            url_tld = tldextract.extract(url).suffix
        except:
            url_tld= None
        if is_tld(url_tld):
            return 0 # valid tld
        return 1 # not valid
    
def check_dns_record(url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        return dns

    # Check if exists https

def check_https(url):
        scheme = urlparse(url).scheme
        match = str(scheme) 
        if match =='https':
            return 0 # True : https
        else:
            return 1 # Fasle: http,ftp ....
        

def check_subdomains(url):
        parsed_url = urlparse(url)
        subdomains = parsed_url.netloc.split('.')
        
        if subdomains[0] == 'www' :
            if len(subdomains) - 1 == 3:
                return 2 # suspicious
            elif len(subdomains) - 1 > 3 :
                return 1 # phising
            else :
                return 0 # ok
        else :
            if len(subdomains) == 3:
                return 2 # suspicious
            elif len(subdomains) > 3 :
                return 1 # phising
            else :
                return 0 # ok

    # Count number of http in url

def check_http(url):
        temp = [ match for match in re.finditer("http",url)]
        if len(temp) > 1 :
            return 1
        return 0

    # Check if exists exe/zip

def check_malicious_file_extension(url):
        url = url.lower()
        malicious_file_extension = [".exe",".doc",".docx",".xls",".xlsx",".xlsm",".zip",".rar"]
        matches = re.findall('|'.join(map(re.escape, malicious_file_extension)), url)
        if len(matches) >=1 :
            return 1 #Yes
        else: 
            return 0 # No

    # Check length of url    

def check_length(url):
        # if len(url) < 54:
        #     length = 0
        # else:
        #     length = 1
        # return length
        if len(url) < 54:
            return 0            # legitimate
        elif len(url) >= 54 and len(url) <= 75:
            return 2            # suspicious
        else:
            return 1            # phishing

  
    # Checking for Shortening Services in URL (Tiny_URL)

def check_shorten_URL(url):
        match=re.search(shortening_services,url)
        if match:
            return 1
        else:
            return 0

    # Checking for redirection '//' in the url (Redirection)

def check_redirection(url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1 # Phising
            else:
                return 0
        else:
            return 0                 

    # Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)

def prefix_suffix(url):
        if '-' in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate

def check_symbols(url):
        flag=0
        sc=['@','~','`','!', '$','%','&']
        for i in range(len(sc)):
            if sc[i] in url:
                at = 1
                flag=1
            break
        if flag==0:
            at = 0
        return at

    # def add_feature(data):
    #     data['having_ip_address'] = self.data['url'].apply(lambda i:self.having_IP(i))
    #     data['have_dns'] = self.data['url'].apply(lambda i: self.check_dns_record(i))
    #     self.data['have_https'] = self.data['url'].apply(lambda i: self.check_https(i))
    #     self.data['subdomains'] = self.data['url'].apply(lambda i: self.check_subdomains(i))
    #     self.data['valid_tld'] = self.data['url'].apply(lambda i: self.check_tld(i))
    #     self.data['http'] = self.data['url'].apply(lambda i: self.check_http(i))
    #     self.data['exe&zip'] = self.data['url'].apply(lambda i: self.check_malicious_file_extension(i))
    #     self.data['length'] = self.data['url'].apply(lambda i: self.check_length(i))
    #     self.data['shorten_URL'] = self.data['url'].apply(lambda i: self.check_shorten_URL(i))
    #     self.data['redirection'] = self.data['url'].apply(lambda i: self.check_redirection(i))
    #     self.data['prefix_suffix'] = self.data['url'].apply(lambda i: self.prefix_suffix(i))
    #     self.data['have_@'] = self.data['url'].apply(lambda i: self.check_symbols(i))
        
    # def get_data(self):
    #     return self.data        
        
def check_iframe(url):
    try :
        response = requests.request(url)
    except :
        response = ""
    if response == "":
        return 1
    else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1    




