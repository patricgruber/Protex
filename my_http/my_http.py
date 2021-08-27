from urllib.parse import urlparse
import json


class HTTPHelper:
    SEPARATOR = b"\r\n"

    @staticmethod
    def parse_headers(header_lines):
        headers = {}
        for header in header_lines:
            header_name = ""
            header_str = header.decode()

            if header_str[0] == ':':
                header_name += ':'
                header_str = header_str[1:]

            header_parts = header_str.split(':')
            header_name += header_parts[0]
            header_name = header_name.lower()
            header_content = ":".join(header_parts[1:]).strip()

            headers[header_name] = header_content
        return headers

    @staticmethod
    def headers_to_str(headers):
        header_str = ""
        for key in headers:
            header_str += "\t{}: {}{}"
            header_str = header_str.format(key, headers[key], HTTPHelper.SEPARATOR.decode())
        return header_str


class HTTPRequest:
    def __init__(self, request_dict=None, raw_payload=None, https=True):
        if request_dict:
            self.content = request_dict["content"]
            self.method = request_dict["method"].decode()
            self.url = request_dict["url"]
            self.url_parsed = urlparse(self.url)
            self.http_version = request_dict["http_version"].decode()
            self.https = self.url[:5] == "https"
            self.headers = {key: request_dict["headers"][key] for key in request_dict["headers"]}
        elif not request_dict and raw_payload:
            self.raw_payload = raw_payload
            self.content = ""
            self.method = ""
            self.path = ""
            self.http_version = ""
            self.https = https

            request_parts = raw_payload.split(HTTPHelper.SEPARATOR + HTTPHelper.SEPARATOR)
            header = request_parts[0]
            self.content = (HTTPHelper.SEPARATOR + HTTPHelper.SEPARATOR).join(request_parts[1:])

            headers = header.split(HTTPHelper.SEPARATOR)
            info_parts = headers[0].split(b" ")
            self.method = info_parts[0].decode()
            self.http_version = info_parts[-1].decode()
            url_rest = b" ".join(info_parts[1:-1]).decode()

            self.headers = HTTPHelper.parse_headers(headers[1:])

            host = ""
            if "host" in self.headers:
                host = self.headers["host"]
            elif ":authority" in self.headers:
                host = self.headers[":authority"]

            protocol = "https://"
            if not self.https:
                protocol = "http://"

            self.url = protocol + host + url_rest
            self.url_parsed = urlparse(self.url)

    def get_headers_for_replay(self):
        headers_for_replay = self.headers.copy()
        for key in [":authority", "host"]:  # removed since the host/authority header is set by requests base on the url
            if key in headers_for_replay:
                del headers_for_replay[key]
        return headers_for_replay

    def get_url_path_parts(self):
        parts = self.url_parsed.path.split("/")[1:]  # remove first empty part, because part begins with /
        if parts[-1] == "":  # remove last empty part if path ends with /
            parts = parts[:-1]
        return parts

    def get_url_query_params(self):
        params = {}
        if self.url_parsed.query != "":
            for part in self.url_parsed.query.split("&"):
                parts = part.split("=")
                params[parts[0]] = "" if len(parts) == 1 else parts[1]

        return params

    def get_cookies_pairs(self):
        cookies = {}
        if "cookie" in self.headers:
            for cookie in self.headers["cookie"].split("; "):
                split = cookie.split("=")
                key = split[0]
                # base64 encoded string have more parts
                value = "=".join(split[1:])
                cookies[key] = value
        return cookies

    def __str__(self):
        info = "\tMethod: {}\n\tURL: {}\n\tHTTP-Version: {}\n".format(self.method, self.url, self.http_version)
        header_str = HTTPHelper.headers_to_str(self.headers)
        content = self.content
        return "HTTP-Request: (HTTP{})\nInfo:\n{}Headers:\n{}\nContent:\n{}\n".format("S" if self.https else "", info, header_str, content)

    def __key(self):
        return self.content, self.method, self.url, self.http_version, str(self.headers)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, obj):
        return hash(self) == hash(obj)


class HTTPResponse:
    def __init__(self, response_dict=None, raw_payload=None):
        if response_dict:
            self.headers = {key: response_dict["headers"][key] for key in response_dict["headers"] if key != "set-cookie"}
            if "set-cookie" in response_dict["headers"] and len(response_dict["headers"]["set-cookie"]):
                self.headers["set-cookie"] = response_dict["headers"]["set-cookie"]
            self.content = response_dict["content"]
            self.status_code = response_dict["status_code"]
            self.status_text = response_dict["reason"].decode()
            self.http_version = response_dict["http_version"].decode()
        elif raw_payload:
            self.raw_payload = raw_payload
            self.headers = {}
            self.content = ""
            self.status_code = ""
            self.status_text = ""
            self.http_version = ""

            request_parts = raw_payload.split(HTTPHelper.SEPARATOR + HTTPHelper.SEPARATOR)
            header = request_parts[0]
            self.content = (HTTPHelper.SEPARATOR + HTTPHelper.SEPARATOR).join(request_parts[1:])

            headers = header.split(HTTPHelper.SEPARATOR)
            info_parts = headers[0].split(b" ")
            self.http_version = info_parts[0].decode()
            self.status_code = int(info_parts[1].decode())
            if len(info_parts) > 2:
                self.status_text = info_parts[2].decode()

            self.headers = HTTPHelper.parse_headers(headers[1:])

    def get_set_cookies(self):
        cookies = {}
        if "set-cookie" in self.headers:
            for set_cookie in self.headers["set-cookie"]:
                pair = set_cookie.split(";")[0]
                parts = pair.split("=")
                key = parts[0]
                value = "=".join(parts[1:])
                cookies[key] = value

        return cookies

    def get_json_content(self):
        if "content-type" not in self.headers or not self.headers["content-type"].startswith("application/json"):
            return {}
        content = self.content.decode()
        if len(content.split("\n")[0]) == 4: # begins with )]}' or )]}"
            content = content[5:]
        return json.loads(content)

    def get_url_encoded_content(self):
        if self.headers["content-type"] != "application/x-www-form-urlencoded":
            return {}
        data = {}
        for param in self.content.decode().split("&"):
            key, value = param.split("=")
            data[key] = value
        return data

    def __key(self):
        return self.status_code, self.http_version, str(self.headers), self.content

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, obj):
        return hash(self) == hash(obj)

    def __str__(self):
        info = "\tHTTP-Version: {}\n\tStatus Code: {}\n\tStatus Text: {}\n".format(self.http_version, self.status_code, self.status_text)
        header_str = HTTPHelper.headers_to_str(self.headers)
        content = self.content
        return "HTTP-Response: \nInfo:\n{}Headers:\n{}\nContent:\n{}\n".format(info, header_str, content)
