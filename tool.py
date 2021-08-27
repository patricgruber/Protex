#!/usr/bin/python

from termcolor import colored
import json
import httpx as requests
from lxml import etree
from urllib.parse import quote, unquote
from base64 import b64decode, b64encode
from sys import exit
import time

from helper.parsing_helper import ParsingHelper as pa
from helper.pruning_helper import PruningHelper as pu
from helper.matching_helper import MatchingHelper as ma
from helper.nonces_helper import NoncesHelper as no
from config import TYPES, USE_ORACLE, ORACLE, KNOWN_STRINGS, CONFIGURATION
from helper.my_exceptions import OracleNotUsedException


def fail(string):
    print(colored(string, "red"))


def success(string):
    print(colored(string, "green"))


def prune_before(pairs):
    pairs = pu.prune_by_oracle(pairs)
    if debug:
        print("Oracle pruned HTTP pair count %d" % len(pairs))
    if len(pairs) == 0:
        print(colored("The trace contains no oracle pair. "
                      "Either the oracle was not properly defined or the trace is incomplete.", "blue"))
        exit(-1)
    pairs = pu.prune_http_pairs_statically(pairs)
    if debug:
        print("Statically pruned HTTP pair count %d" % len(pairs))

    return pairs


def prune_after(pairs, response_nonce_set, oracle_pair):
    minimal_prefix = []
    prunable_postfix = pairs[:]

    while len(prunable_postfix) > 0:
        if debug:
            print("Testing %d/%d (%s)..." %
                  (len(minimal_prefix) + 1, len(minimal_prefix) + len(prunable_postfix), prunable_postfix[0][0].url),
                  end=" ")

        worked = False
        if prunable_postfix[0] != oracle_pair:
            candidate_trace = minimal_prefix + prunable_postfix[1:]
            worked = replay_trace_with_nonce_retrieval(candidate_trace, response_nonce_set, oracle_pair)
        elif debug:
            print("Oracle pair", end=" -> ")

        if not worked:
            if debug:
                fail("Needed\n")
            minimal_prefix += [prunable_postfix[0]]
        elif debug:
            success("Pruned\n")
        prunable_postfix = prunable_postfix[1:]

        print("Sleeping for %d secs between dynamic replay runs... " % time_between_dynamic_pruning_runs)
        time.sleep(time_between_dynamic_pruning_runs)

    return minimal_prefix


def prepare_request_for_replay(request, real_nonces):
    req_headers = request.get_headers_for_replay()
    req_content = request.content
    req_url = request.url

    # sort nonces by length descending (longest first)
    old_nonces = sorted(list(real_nonces), key=len, reverse=True)

    # Replace all old nonces in the request with the new nonces
    for old_nonce in old_nonces:
        new_nonce = real_nonces[old_nonce]
        req_headers = {header: req_headers[header].replace(old_nonce, new_nonce) for header in req_headers}
        if 'content-length' in req_headers:
            del req_headers['content-length']
        if 'date' in req_headers:
            del req_headers['date']
        req_content = req_content.replace(old_nonce.encode(), new_nonce.encode())
        req_url = req_url.replace(old_nonce, new_nonce)

    return req_url, req_headers, req_content


def retrieve_nonces(expected_response, actual_response, response_nonce_set, real_nonces):
    # Parse real response to retrieve nonces from it
    if expected_response in response_nonce_set:
        if debug:
            print("Should be able to retrieve: ", response_nonce_set[expected_response])
        for val, id, key in response_nonce_set[expected_response]:
            new_nonce = None
            if id == "json":
                if actual_response.headers["content-type"].startswith("application/json"):
                    content = actual_response.text
                    if len(content.split("\n")[0]) == 4:  # begins with )]}' or )]}"
                        content = content[5:]
                    parsed_json_content = json.loads(content)
                    flattend = {key: str(value) for key, value in pa.flatten_json(parsed_json_content)}
                    if key in flattend:
                        new_nonce = flattend[key]
            elif id == "form-urlencoded":
                parsed = pa.parse_form_url_encoded(actual_response.text)
                new_nonce = parsed[key]
            elif id == "set-cookie" and "set-cookie" in actual_response.headers:
                set_cookie_headers = [value.decode() for key, value in actual_response.headers.raw if
                                      key.decode().lower() == "set-cookie"]
                for set_cookie_header in set_cookie_headers:
                    name, value = pa.parse_set_cookie_header(set_cookie_header)
                    if key == name:
                        new_nonce = value
            elif id.startswith("meta-redirect-"):
                url_part = id[len("meta-redirect-"):]
                if actual_response.status_code == 302:  # some sites randomly choose to use location header or meta redirect
                    meta_refresh_url = actual_response.headers["location"]
                else:
                    meta_refresh_url = pa.parse_meta_refresh_url_from_content(actual_response.content.decode())
                if meta_refresh_url:
                    new_nonce = pa.get_url_part(meta_refresh_url, url_part, key)
            elif id.startswith("location-"):
                part = id[len("location-"):]
                location_url = None
                if actual_response.status_code == 200:  # some sites randomly choose to use location header or meta redirect
                    meta_redirect_url = pa.parse_meta_refresh_url_from_content(actual_response.content.decode())
                    if meta_redirect_url:
                        location_url = meta_redirect_url
                elif "location" in actual_response.headers:
                    location_url = actual_response.headers["location"]
                if location_url:
                    new_nonce = pa.get_url_part(location_url, part, key)
            elif id == "html-hidden-input":
                dom = etree.HTML(actual_response.content.decode())
                elements = dom.xpath(key)
                if len(elements) > 0:
                    new_nonce = elements[0].get("value")

            elif debug:
                fail("I don't know nonces of type %s" % id)

            if new_nonce:
                if debug:
                    success("Retrieved new nonce {}({}): {}->{}".format(id, key, val, new_nonce))

                val = best_effort_decode(val)
                new_nonce = best_effort_decode(new_nonce)

                def base64encode(val):
                    return b64encode(val.encode()).decode()

                def base64decode(val):
                    return b64decode(val.encode()).decode()

                def quote_with_slash(val):
                    return quote(val, safe='')

                encodings = [quote_with_slash, unquote, base64encode, base64decode, lambda x: x]

                for encoding in encodings:
                    try:
                        real_nonces[encoding(val)] = encoding(new_nonce)
                    except Exception:
                        pass
            elif debug:
                fail("Couldn't retrieve new nonce {}({})".format(id, key))


def best_effort_decode(value):
    try:
        if isinstance(value, (bytes, bytearray)):
            value = value.decode()
    except:
        return value

    try:
        value = unquote(value)
    except:
        pass

    try:
        value = b64decode(value.encode()).decode()
    except:
        pass

    return value


def replay_trace_with_nonce_retrieval(trace, response_nonce_set, oracle_pair, show_debug=None):
    global debug
    local_debug = debug
    if show_debug is not None:
        local_debug = show_debug
    real_nonces = {}
    session = requests
    return_value = None

    for request, response in trace:
        req_url, req_headers, req_content = prepare_request_for_replay(request, real_nonces)

        print("Requesting %s " % req_url)

        res = session.request(request.method, req_url, data=req_content, headers=req_headers, allow_redirects=False)

        if res.status_code != response.status_code:
            if not (res.status_code == response.status_code or
                    res.status_code in [200, 302] and response.status_code in [200, 302]):
                if local_debug:
                    fail("\tSomething is wrong (Expected: %d, Got: %d)" % (response.status_code, res.status_code))
            else:
                if local_debug:
                    print("\tTrying to fix this by allowing redirects... ", end="")
                res = session.request(request.method, req_url, data=req_content, headers=req_headers,
                                      allow_redirects=True)
                if local_debug:
                    if res.status_code != response.status_code:
                        fail("\tSomething is wrong again! (Expected: %d, Got: %d)" % (
                            response.status_code, res.status_code))
                    else:
                        success("\tFixing it seems to have worked!")

        if res.status_code == response.status_code or res.status_code in [200, 302] and response.status_code in [200,
                                                                                                                 302]:
            retrieve_nonces(response, res, response_nonce_set, real_nonces)

        if (request, response) == oracle_pair:
            return_value = ORACLE(res.status_code, res.headers, res.content)

    if return_value is None:
        raise OracleNotUsedException
    return return_value


def get_type_of_string(string):
    for regex, name in TYPES:
        if regex.fullmatch(string):
            return name
    return "unknown"


def prepare_nonce_sets_for_abstraction(request_nonces, response_nonces):
    prepared_nonces = {}
    i = 0
    for _, val, _, _ in request_nonces:
        if val not in prepared_nonces:
            type = get_type_of_string(val)
            prepared_nonces[val] = "<request_nonce_%d::%s>" % (i, type)
            i += 1
    i = 0
    for _, val, _, _ in response_nonces:
        if val not in prepared_nonces:
            type = get_type_of_string(val)
            prepared_nonces[val] = "<response_nonce_%d::%s>" % (i, type)
            i += 1
    return prepared_nonces


def replace_all_in_string(string, replacements):
    new_string = string
    for old_val in replacements:
        new_val = replacements[old_val]
        new_string = new_string.replace(old_val, new_val)
    return new_string


def abstract_trace(trace, replacements):
    abstracted_trace = []
    for req, res in trace:
        def replace_headers_and_content(http):
            abstracted_headers = {
                header: replace_all_in_string(http.headers[header], replacements)
                for header in http.headers if header != "set-cookie"
            }
            if "set-cookie" in http.headers:
                abstracted_headers["set-cookie"] = [replace_all_in_string(value, replacements) for value in
                                                    http.headers["set-cookie"]]

            try:
                abstracted_content = replace_all_in_string(http.content.decode(), replacements)
            except UnicodeDecodeError:
                return abstracted_headers, None

            return abstracted_headers, abstracted_content

        # abstract the request
        abstracted_headers, abstracted_content = replace_headers_and_content(req)
        if abstracted_content is None:
            continue
        abstracted_request = {
            "url": replace_all_in_string(req.url, replacements),
            "headers": abstracted_headers,
            "method": req.method,
            "content": abstracted_content
        }

        # abstract the response
        abstracted_headers, abstracted_content = replace_headers_and_content(res)
        if abstracted_content is None:
            continue

        abstracted_response = {
            "status_code": res.status_code,
            "headers": abstracted_headers,
            "content": abstracted_content
        }
        abstracted_trace.append({"request": abstracted_request, "response": abstracted_response})

    return abstracted_trace


def contains_any(string, string_set):
    for str in string_set:
        if str in string:
            return True
    return False


def prepare_response_nonces(response_nonces):
    response_nonce_set = {}
    for res, val, id, key in response_nonces:
        if res not in response_nonce_set:
            response_nonce_set[res] = []
        response_nonce_set[res].append((val, id, key))
    return response_nonce_set


def determine_file_names():
    file1 = ""
    file2 = ""
    output_file = ""
    return file1, file2, output_file


def parse_input_files(file1, file2):
    pairs1 = pa.parse_file(file1)
    print("Pairs before pruning: %d" % len(pairs1))
    pairs1 = prune_before(pairs1)

    pairs2 = pa.parse_file(file2)
    print("Pairs before pruning: %d" % len(pairs2))
    pairs2 = prune_before(pairs2)

    return pairs1, pairs2


def write_result_file(output_file, pruned_pairs, request_nonces, response_nonces):
    used_requests = [req for req, _ in pruned_pairs]
    used_responses = [res for _, res in pruned_pairs]
    used_request_nonces = {(r, val, i, key) for r, val, i, key in request_nonces if r in used_requests}
    used_response_nonces = {(r, val, i, key) for r, val, i, key in response_nonces if r in used_responses}
    prepared_nonces = prepare_nonce_sets_for_abstraction(used_request_nonces, used_response_nonces)
    replacements = prepared_nonces.copy()
    for known_string in KNOWN_STRINGS:
        replacements[known_string] = "<user-defined:%s>" % KNOWN_STRINGS[known_string]
    print("Prepared nonces/replacements:")
    for k_s in replacements:
        print("\t %s -> %s" % (replacements[k_s], k_s))
    print("-" * 100)
    if CONFIGURATION["SHOULD_ABSTRACT_OUTPUT"]:
        abstracted = pruned_pairs
    else:
        abstracted = abstract_trace(pruned_pairs, replacements)
    with open(output_file, "w") as opened_file:
        json.dump(abstracted, opened_file)
    print("Finished! Written the output to %s" % output_file)


def find_valid_matching(possible_matches, trace1):
    first_match, found, trace, request_nonces, response_nonces, oracle_pair = None, False, None, None, None, None
    i = 1
    for possible_match in possible_matches:
        if first_match is None:
            first_match = possible_match
        request_nonces, response_nonces = no.find_nonces(possible_match)
        trace = [pair1 for pair1, _ in possible_match]

        if print_urls:
            print("\nMatched URLs:")
            for pair in trace1:
                prefix = "  "
                if pair in trace:
                    prefix = "+ "
                print(prefix + pair[0].url)
            print()

        if debug:
            print("Found nonces:")
            print("Request nonces:")
            for request, value, type, key in request_nonces:
                print("URL: %s in %s\n\t%s=%s" % (request.url, type, key, value), end="\n\n")

            print("Response nonces:")
            for response, value, type, key in response_nonces:
                request = list(filter(lambda x: x is not None,
                                      [pair[0] if pair[1] == response else None for pair in trace]))[0]
                print("URL: %s in %s\n\t%s=%s" % (request.url, type, key, value), end="\n\n")
            print("-" * 100)

        if not any([USE_ORACLE(p) for p in trace]):
            print("No oracle pair found. Skipping this matching.")
            i += 1
            continue
        oracle_pair = [p for p in trace if USE_ORACLE(p)][-1]
        response_nonce_set = prepare_response_nonces(response_nonces)

        if replay_trace_with_nonce_retrieval(trace, response_nonce_set, oracle_pair, False):
            found = True
            success("Replay worked")
            break
        fail("Replay failed")
        i += 1
    return first_match, found, oracle_pair, request_nonces, response_nonce_set, response_nonces, trace


def pruned_found_matching(first_match, found, oracle_pair, request_nonces, response_nonce_set, response_nonces,
                          trace):
    if found:
        if debug:
            print("Nonces that can't be retrieved during replaying, "
                  "because they just magically appear on the sending side")
            for req, _, id, key in request_nonces:
                print(colored("\t%s - %s %s" % (req.url, id, key), "red"))
        print("Nonces that can't be retrieved: %d" % len({v for _, v, _, _ in request_nonces}))

        if print_urls:
            print("\nURLs:")
            for request, _ in trace:
                print("> " + request.url)
            print()

        pruned_pairs = prune_after(trace, response_nonce_set, oracle_pair)
    else:
        fail("Found no replayable matching")
        print("Found no match of the two traces that is replayable. Using first match and skipping dynamic pruning.")
        request_nonces, response_nonces = no.find_nonces(first_match)
        pruned_pairs = [pair1 for pair1, _ in first_match]

        if print_urls:
            print("\nURLs:")
            for pair in trace:
                prefix = "  "
                if pair in trace:
                    prefix = "+ "
                print(prefix + pair[0].url)
            print()
    return pruned_pairs, request_nonces, response_nonces


time_between_dynamic_pruning_runs = CONFIGURATION["TIME_BETWEEN_DYNAMIC_PRUNING_RUNS"]
debug = CONFIGURATION["DEBUG"]
print_urls = CONFIGURATION["SHOULD_PRINT_URLS_FOR_MATCHINGS"]


def main():
    file1, file2, output_file = determine_file_names()
    trace1, trace2 = parse_input_files(file1, file2)
    possible_matches = ma.match_two_traces(trace1, trace2)

    first_match, found, oracle_pair, request_nonces, response_nonce_set, response_nonces, found_trace = \
        find_valid_matching(possible_matches, trace1)

    pruned_pairs, request_nonces, response_nonces = pruned_found_matching(first_match, found, oracle_pair,
                                                                          request_nonces, response_nonce_set,
                                                                          response_nonces, found_trace)
    print("#" * 400)

    write_result_file(output_file, pruned_pairs, request_nonces, response_nonces)


if __name__ == "__main__":
    main()
