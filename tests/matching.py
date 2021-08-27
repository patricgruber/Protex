import sys

sys.path.append('../')

import unittest

from my_http.my_http import *
from helper.matching_helper import MatchingHelper as ma


def create_http_pair_with_url(url):
    request = HTTPRequest({
        'url': url,
        'content': '',
        'method': b'',
        'http_version': b'',
        'headers': []
    })
    response = HTTPResponse({
        'headers': [],
        'content': '',
        'status_code': 100,
        'reason': b'',
        'http_version': b''
    })

    return request, response


def matching_to_str(matching):
    matching_string = ""
    for match in matching:
        matching_string += match[0][0].url
        matching_string += " <-> "
        matching_string += match[1][0].url
        matching_string += " | "
    return matching_string


def print_matchings(matchings):
    i = 1
    for matching in matchings:
        print("Matching " + str(i))
        for match in matching:
            print(match[0][0].url + " <-> " + match[1][0].url)
        i += 1


class TestComplexMatch(unittest.TestCase):

    def test_trivial_count(self):
        trace1 = [create_http_pair_with_url("http://a.com/")]
        trace2 = [create_http_pair_with_url("http://a.com/")]

        matchings = list(ma.match_two_traces(trace1, trace2))
        self.assertEqual(len(matchings), 1)

    def test_simple_count(self):
        trace1 = [
            create_http_pair_with_url("http://a.com/"),
            create_http_pair_with_url("http://b.com/"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/"),
            create_http_pair_with_url("http://b.com/"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))
        self.assertEqual(len(matchings), 3)

    def test_swap_count(self):
        trace1 = [
            create_http_pair_with_url("http://b.com/"),
            create_http_pair_with_url("http://a.com/"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/"),
            create_http_pair_with_url("http://b.com/"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))
        self.assertEqual(len(matchings), 2)

    def test_medium_count(self):
        trace1 = [
            create_http_pair_with_url("http://a.com/"),
            create_http_pair_with_url("http://b.com/"),
            create_http_pair_with_url("http://c.com/"),
            create_http_pair_with_url("http://d.com/"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/"),
            create_http_pair_with_url("http://b.com/"),
            create_http_pair_with_url("http://d.com/"),
            create_http_pair_with_url("http://c.com/"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))

        self.assertEqual(len(matchings), 11)

    def test_simple_multiple_possibilities_count(self):
        trace1 = [
            create_http_pair_with_url("http://a.com/1"),
            create_http_pair_with_url("http://a.com/2"),
            create_http_pair_with_url("http://b.com/"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/a"),
            create_http_pair_with_url("http://a.com/b"),
            create_http_pair_with_url("http://b.com/"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))

        self.assertEqual(len(matchings), 11)

    def test_multiple_possibilities_count(self):
        trace1 = [
            create_http_pair_with_url("http://a.com/1"),
            create_http_pair_with_url("http://a.com/2"),
            create_http_pair_with_url("http://b.com/1"),
            create_http_pair_with_url("http://b.com/2"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/a"),
            create_http_pair_with_url("http://a.com/b"),
            create_http_pair_with_url("http://b.com/a"),
            create_http_pair_with_url("http://b.com/b"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))

        self.assertEqual(len(matchings), 35)

    def test_more_multiple_possibilities_count(self):
        trace1 = [
            create_http_pair_with_url("http://a.com/1"),
            create_http_pair_with_url("http://a.com/2"),
            create_http_pair_with_url("http://b.com/1"),
            create_http_pair_with_url("http://b.com/2"),
            create_http_pair_with_url("http://c.com/1"),
            create_http_pair_with_url("http://c.com/2"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/a"),
            create_http_pair_with_url("http://a.com/b"),
            create_http_pair_with_url("http://b.com/a"),
            create_http_pair_with_url("http://b.com/b"),
            create_http_pair_with_url("http://c.com/a"),
            create_http_pair_with_url("http://c.com/b"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))

        self.assertEqual(len(matchings), 215)

    def test_chaotic_count(self):
        trace1 = [
            create_http_pair_with_url("http://a.com/1"),
            create_http_pair_with_url("http://a.com/2"),
            create_http_pair_with_url("http://b.com/"),
            create_http_pair_with_url("http://c.com/1"),
            create_http_pair_with_url("http://c.com/2"),
            create_http_pair_with_url("http://a.com/3"),
        ]
        trace2 = [
            create_http_pair_with_url("http://a.com/a"),
            create_http_pair_with_url("http://a.com/b"),
            create_http_pair_with_url("http://d.com/"),
            create_http_pair_with_url("http://c.com/a"),
            create_http_pair_with_url("http://c.com/b"),
        ]

        matchings = list(ma.match_two_traces(trace1, trace2))

        self.assertEqual(len(matchings), 39)


if __name__ == '__main__':
    unittest.main()
