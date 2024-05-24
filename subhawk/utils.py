import dns.exception
import dns.resolver
import tldextract
import validators
from rich import print

dns_queries_made = 0
def extract_domain(input_str: str, sub: bool) -> str | None:
    """
    Extracts the domain or subdomain from a given input.

    Args:
        input_str (str): The URL or domain from which to extract the subdomain or domain.
        sub (bool): If True, extracts the subdomain along with the domain and TLD. If False, extracts only the domain and TLD.

    Returns:
        str: The extracted subdomain (if requested), domain, and top-level domain (TLD), concatenated, or None if extraction fails.

    Example:
        >>> extract_domain("https://test.example.com", True)
        'test.example.com'
        >>> extract_domain("https://test.example.com", False)
        'example.com'
    """
    try:
        domain = input_str.strip().replace(' ', '')
        extracted = tldextract.extract(domain)
        domain_part = extracted.domain + '.' + extracted.suffix
        
        if sub and extracted.subdomain:
            subdomain_part = extracted.subdomain + '.' + domain_part
            if validators.domain(subdomain_part):
                return subdomain_part
        elif validators.domain(domain_part):
            return domain_part
        else:
            return None
    except Exception:
        return None

def resolve_cname(domain: str) -> list | int:
    global dns_queries_made
    """
    Resolve CNAME records recursively until the final target is reached.

    Args:
        domain (str): The domain or host to resolve.

    Returns:
        list: A list of CNAME targets.
        int: Temporarily returns the number of dns queries we made for debugging purposes.
    """
    domain = extract_domain(domain, True)
    cname_results = []
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        dns_queries_made+=1
        for rdata in answers:
            cname_results.append(str(rdata.target))
            # Im not 100% sure about this, maybe sometimes a cname is pointing to another vulnerable cname?
            # ¯\_(ツ)_/¯
            cname_results.extend(resolve_cname(str(rdata.target)))
            dns_queries_made+=1

    except Exception as e:
        pass

    return cname_results

def is_nxdomain(domain: str) -> bool:
    global dns_queries_made
    """
    Check if the query name does not exist

    Args:
    - domain (str): The domain to check.

    Returns:
    - bool: True if the domain does not exist, False otherwise. 
    """
    try:
        dns.resolver.resolve(domain)
        dns_queries_made+=1
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return True
    except dns.exception.DNSException:
        pass

    return False

def generate_resumecfg(resume_from: str) -> None:
    """Generate a resume configuration file with the provided resume target."""
    with open('resume.cfg', 'w') as file:
        file.write(f"resume_from={resume_from}")

def resume(config: str) -> str | None:
    """Read the resume target from the provided configuration file."""
    try:
        with open(config, 'r') as file:
            lines = file.read().splitlines()
            resume_from = lines[0].split('=')[1]
            return resume_from
    except:
        return None


def save_result(result:str, output: str) -> None:
    """Writes result to provided file, Writes to 'results.txt' when output file is not provided."""
    if output is None:
        output = "results.txt"
    with open(output, 'a') as file:
        file.write(f"Vulnerable: {result}\n")

def print_logs():
    from subhawk.subhawk import http_requests_made
    if http_requests_made:
        print(f"[medium_violet_red bold][𝖉𝖊𝖇𝖚𝖌][/] Made a total of {http_requests_made} http requests.")
    if dns_queries_made:
        print(f"[medium_violet_red bold][𝖉𝖊𝖇𝖚𝖌][/] Made a total of {dns_queries_made} dns queries.")

def format_time(seconds):
    intervals = (
        ('weeks', 604800),
        ('days', 86400),
        ('hours', 3600),
        ('minutes', 60),
        ('seconds', 1),
    )
    result = []
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append(f"{int(value)} {name}")
    return ', '.join(result)
