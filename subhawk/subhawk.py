import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from subhawk.constants import CNAMES, FINGERPRINT, HEADERS, HTTP_STATUS, NXDOMAIN
from subhawk.utils import extract_domain, resolve_cname, is_nxdomain

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

http_requests_made = 0

def takeover(target: str) -> str | None:
    """Checks for potential subdomain takeover."""
    cnames = resolve_cname(target)
    for cname in cnames:
        target_domain = cname.rstrip('.')
        if any(target_domain.endswith(cname_suffix) for cname_suffix in CNAMES):
            service = extract_domain(cname, False)
            result = validate_tko(target_domain, service)
            if result:
                return result
            
    return None

def validate_tko(target_domain: str, service: str) -> str | None:
    global http_requests_made
    if service not in FINGERPRINT:
        return None
    
    if FINGERPRINT[service] == NXDOMAIN:
        if is_nxdomain(target_domain):
            return target_domain
    
    target_fingerprint = FINGERPRINT.get(service)
    url = f"http://{target_domain}/"

    try:
        response = requests.get(url, headers=HEADERS, allow_redirects=True, timeout=10, verify=False)
        http_requests_made+=1 

        if target_fingerprint.startswith(HTTP_STATUS):
            _, code = target_fingerprint.split("=")
            code = int(code)
            
            if response.status_code == code:
                return target_domain
            
            if response.history:
                for resp in response.history:
                    if resp.status_code == code:
                        return target_domain
            return None

        if target_fingerprint in response.text:
            return target_domain
        
        return None
    except requests.RequestException as e:
        pass

    return None

