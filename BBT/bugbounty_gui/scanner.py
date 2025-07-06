# scanner.py
# This module will handle bug bounty vulnerability scans.
import requests
import os
import datetime

def run_scan(target_url, save_report=True, ai_summary=False, openai_api_key=None):
    results = []
    try:
        resp = requests.get(target_url, timeout=10, allow_redirects=True)
        results.append(f"[+] HTTP Status: {resp.status_code}")
        server = resp.headers.get('Server', 'Unknown')
        results.append(f"[+] Server Header: {server}")
        # Directory listing
        if 'Index of /' in resp.text:
            results.append("[!] Directory listing enabled!")
        # Clickjacking
        if 'X-Frame-Options' not in resp.headers:
            results.append("[!] X-Frame-Options header missing (possible clickjacking)")
        # CORS
        if resp.headers.get('Access-Control-Allow-Origin') == '*':
            results.append("[!] CORS misconfiguration: Access-Control-Allow-Origin is *")
        # Sensitive files
        for sensitive in ['.env', '.git/config', 'robots.txt']:
            try:
                s_url = target_url.rstrip('/') + '/' + sensitive
                s_resp = requests.get(s_url, timeout=5)
                if s_resp.status_code == 200 and len(s_resp.text) > 0:
                    results.append(f"[!] Sensitive file exposed: {sensitive}")
            except Exception:
                pass
        # Basic XSS test
        xss_payload = '<script>alert(1)</script>'
        xss_url = target_url + ("?q=" if '?' not in target_url else "&q=") + xss_payload
        xss_resp = requests.get(xss_url, timeout=10)
        if xss_payload in xss_resp.text:
            results.append("[!] Possible Reflected XSS detected!")
        else:
            results.append("[+] No reflected XSS found.")
        # Open redirect test
        redirect_payload = 'https://example.com'
        redirect_url = target_url + ("?next=" if '?' not in target_url else "&next=") + redirect_payload
        redir_resp = requests.get(redirect_url, timeout=10, allow_redirects=False)
        if redir_resp.status_code in [301, 302, 303, 307, 308] and 'example.com' in redir_resp.headers.get('Location', ''):
            results.append("[!] Possible Open Redirect detected!")
        else:
            results.append("[+] No open redirect found.")
        # Basic SQLi test
        sqli_payload = "' OR '1'='1"
        sqli_url = target_url + ("?id=" if '?' not in target_url else "&id=") + sqli_payload
        sqli_resp = requests.get(sqli_url, timeout=10)
        sqli_errors = ["sql syntax", "mysql_fetch", "syntax error", "unclosed quotation"]
        if any(e in sqli_resp.text.lower() for e in sqli_errors):
            results.append("[!] Possible SQL Injection vulnerability!")
        else:
            results.append("[+] No SQLi found.")
        # HTTP Methods
        try:
            options_resp = requests.options(target_url, timeout=5)
            allow = options_resp.headers.get('Allow', '')
            if any(m in allow for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT']):
                results.append(f"[!] Insecure HTTP methods allowed: {allow}")
            else:
                results.append(f"[+] Allowed HTTP methods: {allow}")
        except Exception:
            pass
        # Security headers
        for header, desc in [
            ('Content-Security-Policy', 'Content Security Policy'),
            ('Strict-Transport-Security', 'Strict Transport Security'),
            ('X-Content-Type-Options', 'X-Content-Type-Options')
        ]:
            if header not in resp.headers:
                results.append(f"[!] Missing security header: {desc}")
        # Exposed API endpoints
        for api_path in ['/api', '/swagger']:
            try:
                api_url = target_url.rstrip('/') + api_path
                api_resp = requests.get(api_url, timeout=5)
                if api_resp.status_code == 200 and len(api_resp.text) > 0:
                    results.append(f"[!] Possible exposed API endpoint: {api_path}")
            except Exception:
                pass
        # Default credentials (very basic, only for /login)
        try:
            login_url = target_url.rstrip('/') + '/login'
            login_resp = requests.post(login_url, data={'username':'admin','password':'admin'}, timeout=5)
            if 'incorrect' not in login_resp.text.lower() and login_resp.status_code == 200:
                results.append("[!] Possible default credentials (admin/admin) accepted on /login!")
        except Exception:
            pass
        # Exposed admin panels
        for admin_path in ['/admin', '/administrator', '/admin/login', '/wp-admin']:
            try:
                admin_url = target_url.rstrip('/') + admin_path
                admin_resp = requests.get(admin_url, timeout=5)
                if admin_resp.status_code == 200 and 'login' in admin_resp.text.lower():
                    results.append(f"[!] Possible exposed admin panel: {admin_path}")
            except Exception:
                pass
        # Weak SSL/TLS (just check if using HTTP)
        if target_url.startswith('http://'):
            results.append("[!] Target is not using HTTPS (weak SSL/TLS)")
        # HTTP Basic Auth
        if resp.status_code == 401 and 'www-authenticate' in resp.headers:
            results.append("[!] HTTP Basic Auth required!")
        # Large error messages (info leak)
        if 'error' in resp.text.lower() and len(resp.text) > 10000:
            results.append("[!] Large error message detected (possible info leak)")
        # Subdomain takeover (basic CNAME check, only if subdomain)
        import re
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        if parsed.hostname and parsed.hostname.count('.') > 1:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(parsed.hostname, 'CNAME')
                for rdata in answers:
                    if any(x in str(rdata.target) for x in ['github.io', 'herokuapp.com', 'amazonaws.com']):
                        results.append(f"[!] Possible subdomain takeover risk: {rdata.target}")
            except Exception:
                pass
        # Exposed backup/config files
        for backup in ['index.php.bak', 'config.php.old', 'wp-config.php.bak', '.DS_Store', 'Thumbs.db']:
            try:
                b_url = target_url.rstrip('/') + '/' + backup
                b_resp = requests.get(b_url, timeout=5)
                if b_resp.status_code == 200 and len(b_resp.text) > 0:
                    results.append(f"[!] Exposed backup/config file: {backup}")
            except Exception:
                pass
        # HTTP/2 support (protocol check)
        try:
            import httpx
            with httpx.Client(http2=True, timeout=5) as client:
                h2_resp = client.get(target_url)
                if hasattr(h2_resp, 'http_version') and h2_resp.http_version == 'HTTP/2':
                    results.append("[+] HTTP/2 supported.")
        except Exception:
            pass
        # CSP bypass (very basic)
        csp = resp.headers.get('Content-Security-Policy', '')
        if csp and 'unsafe-inline' in csp:
            results.append("[!] CSP may be bypassable: uses 'unsafe-inline'")
        # Weak JWT secret (look for JWT in cookies/headers)
        import re
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
        cookies = resp.cookies.get_dict()
        for k, v in cookies.items():
            if re.match(jwt_pattern, v):
                results.append(f"[!] JWT token found in cookie: {k} (check for weak secret)")
        for h, v in resp.headers.items():
            if re.match(jwt_pattern, v):
                results.append(f"[!] JWT token found in header: {h} (check for weak secret)")
        # Exposed environment variables in response
        env_keywords = ['AWS_SECRET', 'API_KEY', 'SECRET_KEY', 'DATABASE_URL', 'PRIVATE_KEY']
        for keyword in env_keywords:
            if keyword in resp.text:
                results.append(f"[!] Exposed environment variable found: {keyword}")
        # Reflected parameters
        test_param = 'reflectedtest123'
        reflect_url = target_url + ("?test=" if '?' not in target_url else "&test=") + test_param
        reflect_resp = requests.get(reflect_url, timeout=5)
        if test_param in reflect_resp.text:
            results.append("[!] Reflected parameter detected (potential for further fuzzing)")
        # HTTP header injection (CRLF)
        crlf_payload = '%0d%0aInjectedHeader:injected'
        crlf_url = target_url + ("?crlf=" if '?' not in target_url else "&crlf=") + crlf_payload
        crlf_resp = requests.get(crlf_url, timeout=5)
        if 'InjectedHeader:injected' in crlf_resp.text or 'InjectedHeader: injected' in crlf_resp.text:
            results.append("[!] Possible HTTP header injection (CRLF) detected!")
        # CORS with credentials
        if resp.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true' and resp.headers.get('Access-Control-Allow-Origin') == '*':
            results.append("[!] CORS misconfiguration: credentials allowed with wildcard origin!")
        # Exposed GraphQL endpoint
        try:
            gql_url = target_url.rstrip('/') + '/graphql'
            gql_resp = requests.post(gql_url, json={"query":"{__schema{types{name}}}"}, timeout=5)
            if gql_resp.status_code == 200 and 'data' in gql_resp.text:
                results.append("[!] Exposed GraphQL endpoint detected!")
        except Exception:
            pass
        # SSRF basic detection (error-based)
        ssrf_url = target_url + ("?url=" if '?' not in target_url else "&url=") + "http://127.0.0.1:8000"
        try:
            ssrf_resp = requests.get(ssrf_url, timeout=5)
            if any(x in ssrf_resp.text.lower() for x in ["refused", "localhost", "127.0.0.1", "connection error"]):
                results.append("[!] Possible SSRF vulnerability (error-based)")
        except Exception:
            pass
        # Path traversal
        traversal_url = target_url + ("?file=" if '?' not in target_url else "&file=") + "../../etc/passwd"
        try:
            traversal_resp = requests.get(traversal_url, timeout=5)
            if "root:x:" in traversal_resp.text:
                results.append("[!] Path traversal vulnerability detected!")
        except Exception:
            pass
        # RCE basic detection (error-based)
        rce_payloads = [';id', '|id', '&&id']
        for payload in rce_payloads:
            rce_url = target_url + ("?cmd=" if '?' not in target_url else "&cmd=") + payload
            try:
                rce_resp = requests.get(rce_url, timeout=5)
                if any(x in rce_resp.text for x in ["uid=", "gid=", "groups="]):
                    results.append(f"[!] Possible RCE vulnerability with payload: {payload}")
            except Exception:
                pass
        # Exposed version control folders
        for vcf in ['.svn/entries', '.hg/store']:
            try:
                vcf_url = target_url.rstrip('/') + '/' + vcf
                vcf_resp = requests.get(vcf_url, timeout=5)
                if vcf_resp.status_code == 200 and len(vcf_resp.text) > 0:
                    results.append(f"[!] Exposed version control folder: {vcf}")
            except Exception:
                pass
        # Exposed backup database files
        for dbfile in ['db.sql', 'backup.sql', 'database.sqlite', 'db.sqlite3', 'backup.bak']:
            try:
                db_url = target_url.rstrip('/') + '/' + dbfile
                db_resp = requests.get(db_url, timeout=5)
                if db_resp.status_code == 200 and len(db_resp.text) > 0:
                    results.append(f"[!] Exposed backup database file: {dbfile}")
            except Exception:
                pass
        # Exposed archive files
        for archive in ['source.zip', 'backup.tar', 'data.7z', 'archive.rar']:
            try:
                archive_url = target_url.rstrip('/') + '/' + archive
                archive_resp = requests.get(archive_url, timeout=5)
                if archive_resp.status_code == 200 and len(archive_resp.content) > 0:
                    results.append(f"[!] Exposed archive file: {archive}")
            except Exception:
                pass
        # Exposed key/cert files
        for keyfile in ['private.pem', 'server.key', 'certificate.crt']:
            try:
                key_url = target_url.rstrip('/') + '/' + keyfile
                key_resp = requests.get(key_url, timeout=5)
                if key_resp.status_code == 200 and len(key_resp.text) > 0:
                    results.append(f"[!] Exposed key/cert file: {keyfile}")
            except Exception:
                pass
        # Exposed log files
        for logfile in ['error.log', 'access.log', 'debug.log', 'app.log']:
            try:
                log_url = target_url.rstrip('/') + '/' + logfile
                log_resp = requests.get(log_url, timeout=5)
                if log_resp.status_code == 200 and len(log_resp.text) > 0:
                    results.append(f"[!] Exposed log file: {logfile}")
            except Exception:
                pass
        # Exposed editor/backup/temp files
        for temp in ['index.php.bak', 'index.php.old', 'index.php.swp', 'index.php.tmp', '.env.bak', '.env.old', '.env.swp', '.env.tmp']:
            try:
                temp_url = target_url.rstrip('/') + '/' + temp
                temp_resp = requests.get(temp_url, timeout=5)
                if temp_resp.status_code == 200 and len(temp_resp.text) > 0:
                    results.append(f"[!] Exposed temp/backup/editor file: {temp}")
            except Exception:
                pass
        # Exposed .git directory
        try:
            git_url = target_url.rstrip('/') + '/.git/HEAD'
            git_resp = requests.get(git_url, timeout=5)
            if git_resp.status_code == 200 and 'ref:' in git_resp.text:
                results.append('[!] Exposed .git directory detected!')
        except Exception:
            pass
        # Exposed .bash_history
        try:
            bash_url = target_url.rstrip('/') + '/.bash_history'
            bash_resp = requests.get(bash_url, timeout=5)
            if bash_resp.status_code == 200 and len(bash_resp.text) > 0:
                results.append('[!] Exposed .bash_history file detected!')
        except Exception:
            pass
        # Exposed .htaccess
        try:
            htaccess_url = target_url.rstrip('/') + '/.htaccess'
            htaccess_resp = requests.get(htaccess_url, timeout=5)
            if htaccess_resp.status_code == 200 and 'RewriteEngine' in htaccess_resp.text:
                results.append('[!] Exposed .htaccess file detected!')
        except Exception:
            pass
        # Exposed .aws/credentials
        try:
            aws_url = target_url.rstrip('/') + '/.aws/credentials'
            aws_resp = requests.get(aws_url, timeout=5)
            if aws_resp.status_code == 200 and '[default]' in aws_resp.text:
                results.append('[!] Exposed AWS credentials file detected!')
        except Exception:
            pass
        # Exposed .ssh directory
        try:
            ssh_url = target_url.rstrip('/') + '/.ssh/id_rsa'
            ssh_resp = requests.get(ssh_url, timeout=5)
            if ssh_resp.status_code == 200 and 'PRIVATE KEY' in ssh_resp.text:
                results.append('[!] Exposed SSH private key detected!')
        except Exception:
            pass
        # Exposed .docker directory
        try:
            docker_url = target_url.rstrip('/') + '/.docker/config.json'
            docker_resp = requests.get(docker_url, timeout=5)
            if docker_resp.status_code == 200 and 'auths' in docker_resp.text:
                results.append('[!] Exposed Docker config detected!')
        except Exception:
            pass
        # Exposed .npmrc file
        try:
            npmrc_url = target_url.rstrip('/') + '/.npmrc'
            npmrc_resp = requests.get(npmrc_url, timeout=5)
            if npmrc_resp.status_code == 200 and '//' in npmrc_resp.text:
                results.append('[!] Exposed .npmrc file detected!')
        except Exception:
            pass
        # Exposed .ftpconfig file
        try:
            ftpconfig_url = target_url.rstrip('/') + '/.ftpconfig'
            ftpconfig_resp = requests.get(ftpconfig_url, timeout=5)
            if ftpconfig_resp.status_code == 200 and 'protocol' in ftpconfig_resp.text:
                results.append('[!] Exposed .ftpconfig file detected!')
        except Exception:
            pass
        # Exposed .env.production and .env.development files
        for envfile in ['.env.production', '.env.development', '.env.local', '.env.test']:
            try:
                env_url = target_url.rstrip('/') + '/' + envfile
                env_resp = requests.get(env_url, timeout=5)
                if env_resp.status_code == 200 and 'SECRET' in env_resp.text.upper():
                    results.append(f"[!] Exposed environment file detected: {envfile}")
            except Exception:
                pass
        # Exposed .pypirc file
        try:
            pypirc_url = target_url.rstrip('/') + '/.pypirc'
            pypirc_resp = requests.get(pypirc_url, timeout=5)
            if pypirc_resp.status_code == 200 and '[distutils]' in pypirc_resp.text:
                results.append('[!] Exposed .pypirc file detected!')
        except Exception:
            pass
        # Exposed .netrc file
        try:
            netrc_url = target_url.rstrip('/') + '/.netrc'
            netrc_resp = requests.get(netrc_url, timeout=5)
            if netrc_resp.status_code == 200 and 'machine' in netrc_resp.text:
                results.append('[!] Exposed .netrc file detected!')
        except Exception:
            pass
        # Exposed backup/config files in nested folders
        for folder in ['backup', 'config', 'old', 'private', 'secrets']:
            for ext in ['.zip', '.tar', '.gz', '.7z', '.rar', '.bak', '.old', '.sql', '.json', '.env']:
                try:
                    nested_url = target_url.rstrip('/') + f'/{folder}/site{ext}'
                    nested_resp = requests.get(nested_url, timeout=5)
                    if nested_resp.status_code == 200 and len(nested_resp.content) > 0:
                        results.append(f"[!] Exposed file in {folder}/: site{ext}")
                except Exception:
                    pass
        # Exposed backup of robots.txt
        try:
            robots_bak_url = target_url.rstrip('/') + '/robots.txt.bak'
            robots_bak_resp = requests.get(robots_bak_url, timeout=5)
            if robots_bak_resp.status_code == 200 and 'User-agent' in robots_bak_resp.text:
                results.append('[!] Exposed backup robots.txt.bak detected!')
        except Exception:
            pass
        # Exposed backup/config files with date patterns
        import re
        date_patterns = [r'\d{4}-\d{2}-\d{2}', r'\d{8}', r'\d{2}-\d{2}-\d{4}']
        for folder in ['backup', 'config', 'db', 'private', 'secrets']:
            for ext in ['.zip', '.tar', '.gz', '.7z', '.rar', '.bak', '.old', '.sql', '.json', '.env']:
                for pattern in date_patterns:
                    for sep in ['_', '-', '']:
                        for year in ['2023', '2024', '2025']:
                            filename = f"site{sep}{year}{ext}"
                            try:
                                dated_url = target_url.rstrip('/') + f'/{folder}/' + filename
                                dated_resp = requests.get(dated_url, timeout=5)
                                if dated_resp.status_code == 200 and len(dated_resp.content) > 0:
                                    results.append(f"[!] Exposed dated file in {folder}/: {filename}")
                            except Exception:
                                pass
        # Exposed backup/config files with month names
        months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
        for folder in ['backup', 'config', 'db', 'private', 'secrets']:
            for ext in ['.zip', '.tar', '.gz', '.7z', '.rar', '.bak', '.old', '.sql', '.json', '.env']:
                for month in months:
                    for year in ['2023', '2024', '2025']:
                        filename = f"site_{month}{year}{ext}"
                        try:
                            month_url = target_url.rstrip('/') + f'/{folder}/' + filename
                            month_resp = requests.get(month_url, timeout=5)
                            if month_resp.status_code == 200 and len(month_resp.content) > 0:
                                results.append(f"[!] Exposed file in {folder}/: {filename}")
                        except Exception:
                            pass
        # Exposed backup/config files with weekday names
        weekdays = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
        for folder in ['backup', 'config', 'db', 'private', 'secrets']:
            for ext in ['.zip', '.tar', '.gz', '.7z', '.rar', '.bak', '.old', '.sql', '.json', '.env']:
                for day in weekdays:
                    for year in ['2023', '2024', '2025']:
                        filename = f"site_{day}{year}{ext}"
                        try:
                            day_url = target_url.rstrip('/') + f'/{folder}/' + filename
                            day_resp = requests.get(day_url, timeout=5)
                            if day_resp.status_code == 200 and len(day_resp.content) > 0:
                                results.append(f"[!] Exposed file in {folder}/: {filename}")
                        except Exception:
                            pass
        # At the end of the scan, save report if requested
        report_filename = None
        if save_report:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            report_dir = os.path.join(os.path.dirname(__file__), 'reports')
            os.makedirs(report_dir, exist_ok=True)
            report_filename = os.path.join(report_dir, f'scan_{timestamp}.txt')
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(f"Scan results for {target_url}\n\n")
                for line in results:
                    f.write(line + '\n')
        # AI summary if requested
        ai_summary_text = None
        if ai_summary and openai_api_key:
            try:
                import openai
                openai.api_key = openai_api_key
                prompt = f"Summarize these web security findings and suggest next steps:\n" + '\n'.join(results)
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}]
                )
                ai_summary_text = response.choices[0].message['content']
            except Exception as e:
                ai_summary_text = f"[AI Error] {str(e)}"
        return results, report_filename, ai_summary_text
    except Exception as e:
        return [f"[!] Error during scan: {str(e)}"], None, None

def export_latest_report():
    report_dir = os.path.join(os.path.dirname(__file__), 'reports')
    if not os.path.exists(report_dir):
        return None
    reports = [f for f in os.listdir(report_dir) if f.startswith('scan_') and f.endswith('.txt')]
    if not reports:
        return None
    latest = max(reports, key=lambda x: os.path.getctime(os.path.join(report_dir, x)))
    return os.path.join(report_dir, latest)
