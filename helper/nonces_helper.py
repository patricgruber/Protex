from helper.matching_helper import MatchingHelper as ma
from helper.parsing_helper import ParsingHelper as pa
from config import CONFIGURATION

from lxml import etree


class NoncesHelper:
    """
    The different types of nonces:
        in requests:
            - path -> part of the path of the url
            - query -> part of the query of the url
            - fragment -> fragment of the url
            - authorization -> authorization header
            - cookie -> one of the cookies in the cookie header
        in responses:
            - json -> part of the json body
            - form-urlencoded -> part of the form-urlencoded body
            - set-cookie -> set-cookie header
            - meta-redirect-? (? from "path", "query", "fragment") -> part of the redirect url from the meta-redirect url
            - location-? (? from "path", "query", "fragment") -> part of the location url from a redirect
    """

    @staticmethod
    def find_nonces_in_requests(request1, request2, found_nonces, request_nonces):
        debug = CONFIGURATION["DEBUG"]

        req1, req2 = request1, request2
        new_nonces = set()

        # check the requests
        # check URL
        if req1.url != req2.url:
            differences = ma.match_urls(req1.url, req2.url)
            for val, id, key in differences:
                new_nonces.add((req1, val, id, key))

        # check authorization header
        elif "authorization" in req1.headers and "authorization" in req2.headers:
            if req1.headers["authorization"] != req2.headers["authorization"]:
                val = req1.headers["authorization"].split(" ")[1]
                if debug:
                    print("%s - %s | %s: Authorization header different" %
                          (req1.url, req1.headers["authorization"], req2.headers["authorization"]))
                new_nonces.add((req1, val, "authorization", None))

        # check cookie header
        elif "cookie" in req1.headers:
            cookies1 = req1.get_cookies_pairs()
            cookies2 = req2.get_cookies_pairs()
            new_nonces = new_nonces.union(NoncesHelper.find_nonces_in_map(req1, cookies1, cookies2, "cookie", "Cookie"))

        elif debug:
            print("Request to %s match" % req1.url)

        for nonce in new_nonces:
            _, val, _, _ = nonce
            if val not in found_nonces:
                request_nonces.add(nonce)

    @staticmethod
    def find_nonces_in_responses(response1, response2, found_nonces, response_nonces):
        res1, res2 = response1, response2
        new_nonces = set()
        # check response
        if "content-type" in res1.headers and res1.content != res2.content:
            content_type = res1.headers["content-type"].split(";")[0]  # remove charset

            # check json content
            if content_type == "application/json":
                json1 = pa.flatten_json(res1.get_json_content())
                json2 = pa.flatten_json(res2.get_json_content())

                json1_map = {key: value for key, value in json1}
                json2_map = {key: value for key, value in json2}

                new_nonces = new_nonces.union(
                    NoncesHelper.find_nonces_in_map(res1, json1_map, json2_map, "json", "JSON"))

            # check for-urlencoded content
            elif content_type == "application/x-www-form-urlencoded":
                params1 = res1.get_url_encoded_content()
                params2 = res2.get_url_encoded_content()
                new_nonces = new_nonces.union(
                    NoncesHelper.find_nonces_in_map(res1, params1, params2, "form-urlencoded",
                                                    "www-form-urlencoded param")
                )

            # html content
            elif content_type == "text/html":
                dom1 = etree.HTML(res1.content)
                dom2 = etree.HTML(res2.content)

                # check meta data redirects in html response
                urls1 = dom1.xpath("//meta[@http-equiv='refresh']")
                urls2 = dom2.xpath("//meta[@http-equiv='refresh']")
                if len(urls1) > 0 and len(urls2) > 0:
                    meta_element1 = urls1[0]
                    meta_element2 = urls2[0]
                    if meta_element1.get("data-url"):
                        url1 = meta_element1.get("data-url")
                    else:
                        url1 = meta_element1.get("content").split(";url=")[-1]

                    if meta_element2.get("data-url"):
                        url2 = meta_element2.get("data-url")
                    else:
                        url2 = meta_element2.get("content").split(";url=")[-1]

                    if url1 and url2 and url1 != url2:
                        url1 = url1.replace("&amp;", "&")
                        url2 = url2.replace("&amp;", "&")
                        url_diffs = ma.match_urls(url1, url2)
                        for val, part, key in url_diffs:
                            part = "meta-redirect-" + part
                            new_nonces.add((res1, val, part, key))

                # check hidden input fields (csrf tokens)
                hidden_inputs1 = dom1.xpath("//input[@type='hidden']")
                hidden_inputs2 = dom2.xpath("//input[@type='hidden']")

                tree1 = etree.ElementTree(dom1)
                tree2 = etree.ElementTree(dom2)

                path_map1 = {tree1.getpath(inp)
                             if not inp.get("id")
                             else "//input[@id='" + inp.get("id") + "']":

                                 inp.get("value") for inp in hidden_inputs1}

                path_map2 = {tree2.getpath(inp)
                             if not inp.get("id")
                             else "//input[@id='" + inp.get("id") + "']":

                                 inp.get("value") for inp in hidden_inputs2}

                for path in path_map1:
                    if path in path_map2 and path_map1[path] != path_map2[path]:
                        new_nonces.add((res1, path_map1[path], "html-hidden-input", path))

        # check sent cookies
        if "set-cookie" in res1.headers:
            set_cookies1 = res1.get_set_cookies()
            set_cookies2 = res2.get_set_cookies()
            new_nonces = new_nonces.union(
                NoncesHelper.find_nonces_in_map(res1, set_cookies1, set_cookies2, "set-cookie", "Set-Cookie")
            )

        # check redirects
        if str(res1.status_code)[0] == "3" and str(res2.status_code)[0] == "3":
            if "location" in res1.headers and "location" in res2.headers:
                location1 = res1.headers["location"]
                location2 = res2.headers["location"]
                if location1 != location2:
                    url_diffs = ma.match_urls(location1, location2)
                    for val, part, key in url_diffs:
                        part = "location-" + part
                        new_nonces.add((res1, val, part, key))

        def redirect_check(meta_redirect_res, http_redirect_res):
            dom = etree.HTML(meta_redirect_res.content)
            meta_url_elements = dom.xpath("//meta[@http-equiv='refresh']")
            if len(meta_url_elements) == 0:
                return
            meta_url_element = meta_url_elements[0]
            if meta_url_element.get("data-url"):
                meta_url = meta_url_element.get("data-url")
            else:
                meta_url = meta_url_element.get("content").split(";url=")[-1]

            redirect_url = http_redirect_res.headers["location"]
            url_diffs = ma.match_urls(meta_url, redirect_url)
            for val, part, key in url_diffs:
                part = "location-" + part
                new_nonces.add((res1, val, part, key))

        if res1.status_code == 200 and res2.status_code == 302:
            redirect_check(res1, res2)
        elif res1.status_code == 302 and res1.status_code == 200:
            redirect_check(res2, res1)

        for nonce in new_nonces:
            _, val, _, _ = nonce
            if val not in found_nonces:
                if CONFIGURATION["DEBUG"]:
                    print("Found new nonce: ", nonce)
                found_nonces.add(val)
                response_nonces.add(nonce)

    @staticmethod
    def find_nonces_in_map(http_message, map1, map2, identifier_string, human_string):
        nonces = set()
        different_values = []
        if isinstance(map1, list) or isinstance(map2, list):
            pass
        for key in map1:
            if key in map1 and key in map2 and map1[key] != map2[key]:
                different_values.append((key, map1[key], map2[key]))
        for key, value1, value2 in different_values:
            nonces.add((http_message, str(value1), identifier_string, key))
            if CONFIGURATION["DEBUG"]:
                print("%s different: '%s' = '%s' | '%s'" % (human_string, key, value1, value2))
        return nonces

    @staticmethod
    def find_nonces(matches):
        # find all nonces as used in trace1
        found_nonces = set()
        request_nonces = set()
        response_nonces = set()

        for (req1, res1), (req2, res2) in matches:
            NoncesHelper.find_nonces_in_requests(req1, req2, found_nonces, request_nonces)
            NoncesHelper.find_nonces_in_responses(res1, res2, found_nonces, response_nonces)

        if CONFIGURATION["DEBUG"]:
            print("Client side nonces (%d) :" % len(request_nonces), request_nonces)
            print("Server side nonces (%d) :" % len(response_nonces), response_nonces)

        return request_nonces, response_nonces
