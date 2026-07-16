from urllib.parse import urlparse


class URLParser:

    def parse(self, url):

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        special_chars = sum(
            1 for c in url
            if c in "@#$%*-_"
        )

        keywords = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "password",
            "signin"
        ]

        keyword_found = any(
            word in url.lower()
            for word in keywords
        )

        return {
            "url": url,
            "domain": parsed.netloc,
            "length": len(url),
            "special_chars": special_chars,
            "subdomains": domain.count("."),
            "https": url.startswith("https://"),
            "keywords": keyword_found
        }