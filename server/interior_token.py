from secrets import token_bytes as secret_token_bytes
from time import perf_counter_ns, time_ns
from re import search as re_search
from requests import get as requests_get
import hashlib

#important notes : domain must end with . like example.com. not *.example.com and not start with * 
#todo add fqdn verify or correct

identifer_domain = ["muse-ca.example","muse.ca.example"]
DoH_URL = "https://dns.google/resolve?name="

"""
def check_token(paid_token, data = ["domain", "nonce"]):
    pub_key = [0x12345678, 0x90abcdef]
    #Use NIST P-384 to check digest, hard-coded public key
    return True
"""
    
def cname_record(data=["domain","csr"], preffered_id=0):
    return "_"+hashlib.sha1(data[1].encode()).hexdigest().upper()+data[0], "_" + hashlib.sha384(data[1].encode()).upper() + "." + identifer_domain[preffered_id]

def txt_record(data=["domain","csr"], preffered_id=0):
    return data[0], hashlib.sha384(data[1]).hexdigest().upper() + "_" + identifer_domain[preffered_id]

def email_genreate(data=["domain","csr"], preffered_id=0):
    code = secret_token_bytes(48)
    eml_html = "<b><strong>Domain Control Validation</strong></b></br><p>Your Verification Code is <b><strong>" + code + "</strong></b></br><p> From " + identifer_domain[0] + "</p>"
    return eml_html

def check_caa(domain):
    URI=DoH_URL+domain+"&type=CAA&cd=true"
    result = requests_get(URI)
    #right = issue wildcard
    right = [False, False, domain]
    if result.status_code == 200:
        for caa_d in identifer_domain:
            if ',"data":"0 issue \\'+caa_d in result.text:
                right[0] = True
            if ',"data":"0 issuewild \\'+caa_d in result.text:
                right[1] = True
        return right
    else: return False
    
def check_cname(data=["domain","csr"]):
    host, value = cname_record(data)
    URI=DoH_URL+host+"&type=CNAME&cd=true"
    result = requests_get(URI)
    if result.status_code == 200:
        #,"Question":[{"name":"host name","type":5}],"Answer":[{"name":"hostname","type":5,"TTL":\d+,"data":"value"}],"Comment":"Response from *
        if re_search('^*,"Question":[{"name":"' + host + '","type":5}],"Answer":[{"name":"' + host + '","type":5,"TTL":\d+,"data":"' + value + '"}],"Comment":"Response from *$', result.text):
            return host, data[0]
        else: return False
    else: return False

def check_txt(data=["domain","csr"]):
    host, value = cname_record(data)
    URI=DoH_URL+host+"&type=TXT&cd=true"
    result = requests_get(URI)
    if result.status_code == 200:
        #{"name":"host","type":16,"TTL":\d+,"data":"value"},
        if re_search('^{"name":"' + host + '","type":16,"TTL":\d+,"data":"' + value + '*$', result.text):
            return host, data[0]
        else: return False
    else: return False