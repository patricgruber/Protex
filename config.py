import re

# the abstract types, which consist of a regex and a name
TYPES = [
    (re.compile("-?[0-9]*\.[0-9]+"), "decimal"),
    (re.compile("-?[0-9]+"), "integer"),
    (re.compile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"), "url"),
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "email"),
    (re.compile("[a-f0-9]+"), "hex-string"),
    (re.compile("([a-zA-Z0-9_\-]|(%[a-fA-F0-9]{2}))+%[a-fA-F0-9]{2}([a-zA-Z0-9_\-]|(%[a-fA-F0-9]{2}))+"), "url-encoded-string"),
    (re.compile("([a-zA-Z0-9+/_\-,]+={0,3}\.){2}[a-zA-Z0-9+/_\-,]+={0,3}"), "JWT token"),
    (re.compile("[a-zA-Z0-9+/_\-,]+={0,3}"), "base64-string"),
]

# known strings which are replaced during the abstraction phase with the given name
KNOWN_STRINGS = {}


# a function to determine if a certain http pair is the pair that is supposed to be checked by the oracle
# this function can only return true for one of all given http pairs
def USE_ORACLE(pair):
    return False


# the actual oracle function. it gets the status_code the headers and the content of the response
# and returns if this response is as expected
# is only called on the response that is supposed to be checked
def ORACLE(status, headers, content):
    return False


# a function that encodes knowledge of unneeded pairs of the researcher
# it returns true if the pair should be filtered
def CUSTOM_FILTER(pair):
    return False


# the time between pruning runs to avoid rate limiting
# in seconds
CONFIGURATION = {
    "TIME_BETWEEN_DYNAMIC_PRUNING_RUNS": 10,
    "DEBUG": True,
    "SHOULD_PRINT_URLS_FOR_MATCHINGS": True,
    "ONLY_NONCE_VALUES_IN_OUTPUT": False,
    "SHOULD_ABSTRACT_OUTPUT": False
}

