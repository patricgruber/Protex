import pickle
import html
from scapy.all import PcapReader
from lxml import etree

from my_http.my_http import HTTPRequest, HTTPResponse
from urllib.parse import urlparse
from config import CONFIGURATION


class ParsingHelper:
    @staticmethod
    def parse_pcap_file(file):
        packets = [ParsingHelper.unpack_to_http_payload(packet) for packet in ParsingHelper.read_pcap_file(file)]
        parsed = ParsingHelper.parse_packets(packets)
        pairs = ParsingHelper.parse_http_pairs(parsed)

        if CONFIGURATION["DEBUG"]:
            print("Intial packet count %d" % len(packets))
            print("Parsed packet count %d" % len(parsed))
            print("HTTP request/response count %d" % len(pairs))

        return pairs

    @staticmethod
    def parse_pickle_file(file):
        with open(file, "rb") as input_file:
            pairs = pickle.load(input_file)

        if CONFIGURATION["DEBUG"]:
            print("HTTP request/response count %d" % len(pairs))

        return [(HTTPRequest(request_dict=pair["request"]),
                 HTTPResponse(response_dict=pair["response"]))
                for pair in pairs]

    @staticmethod
    def parse_file(file):
        if file.endswith("pcap"):
            return ParsingHelper.parse_pcap_file(file)
        elif file.endswith("pkl"):
            return ParsingHelper.parse_pickle_file(file)

    @staticmethod
    def unpack_to_http_payload(packet):
        return bytes(packet.load), packet.dport == 443

    @staticmethod
    def is_request(payload):
        return payload[:4] != b"HTTP"

    @staticmethod
    def read_pcap_file(file):
        packets = [packet for packet in PcapReader(file)]
        print(packets[0])
        return packets

    @staticmethod
    def parse_packets(packets):
        parsed_packets = []
        for raw, is_https in packets:
            try:
                if ParsingHelper.is_request(raw):
                    parsed_packets.append(HTTPRequest(raw_payload=raw, https=is_https))
                else:
                    parsed_packets.append(HTTPResponse(raw_payload=raw))
            except UnicodeDecodeError:
                pass
        return parsed_packets

    @staticmethod
    def parse_http_pairs(parsed_packets):
        pairs = []
        pair = (None, None)
        for i in range(len(parsed_packets)):
            packet = parsed_packets[i]
            if isinstance(packet, HTTPRequest):
                pair = (packet, None)
            else:
                req, _ = pair
                pairs.append((req, packet))
        return pairs

    @staticmethod
    def flatten_json(json):
        out = []

        def flatten(subtree, name=""):
            if isinstance(subtree, dict):
                for node in subtree:
                    flatten(subtree[node], "%s|%s" % (name, node))
            elif isinstance(subtree, list):
                i = 0
                for node in subtree:
                    flatten(node, "%s|%d" % (name, i))
                    i += 1
            else:
                out.append((name, subtree))

        flatten(json)
        return out

    @staticmethod
    def parse_form_url_encoded(form_url_encoded):
        params_map = {}
        for param in form_url_encoded.split("&"):
            key, value = param.split(":")
            params_map[key] = value
        return params_map

    @staticmethod
    def parse_query_from_url(url):
        parsed = urlparse(url)
        if not parsed.query:
            return {}
        return {part.split("=")[0]: part.split("=")[1] for part in parsed.query.split("&")}

    @staticmethod
    def parse_path_from_url(url):
        return [part for part in urlparse(url).path.split("/") if part != ""]

    @staticmethod
    def parse_fragment_form_url(url):
        return urlparse(url).fragment

    @staticmethod
    def parse_url_part(url, part):
        if part == "query":
            return ParsingHelper.parse_query_from_url(url)
        if part == "path":
            return ParsingHelper.parse_path_from_url(url)
        if part == "fragment":
            return ParsingHelper.parse_fragment_form_url(url)

    @staticmethod
    def parse_meta_refresh_url_from_content(content):
        dom = etree.HTML(content)
        meta_tags = dom.xpath("//meta[@http-equiv='refresh']")
        if len(meta_tags) == 0:
            return None
        meta_tag = meta_tags[0]
        if meta_tag.get("data-url"):
            return meta_tag.get("data-url")
        return html.unescape(meta_tag.split(";url=")[1])

    @staticmethod
    def get_url_part(url, part, key):
        parsed = ParsingHelper.parse_url_part(url, part)
        if part == "fragment":
            return parsed
        try:
            return parsed[key]
        except KeyError or IndexError:
            return None

    @staticmethod
    def parse_set_cookie_header(set_cookie_string):
        pair = set_cookie_string.split(";")[0]
        parts = pair.split("=")
        key = parts[0]
        value = "=".join(parts[1:])
        return key, value
