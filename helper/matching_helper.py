from helper.parsing_helper import ParsingHelper as pa
from z3 import *


class MatchingHelper:
    @staticmethod
    def url_and_path_equals(request1, request2):
        url1 = request1.url_parsed.scheme + "://" + request1.url_parsed.netloc + request1.url_parsed.path
        url2 = request2.url_parsed.scheme + "://" + request2.url_parsed.netloc + request2.url_parsed.path
        return url1 == url2

    @staticmethod
    def url_equals(request1, request2):
        url1 = request1.url_parsed.scheme + "://" + request1.url_parsed.netloc
        url2 = request2.url_parsed.scheme + "://" + request2.url_parsed.netloc
        return url1 == url2

    @staticmethod
    def url_similar(request1, request2):
        return request1.method == request2.method \
               and MatchingHelper.url_equals(request1, request2) \
               and len(request1.get_url_path_parts()) == len(request2.get_url_path_parts()) \
               and len(request1.get_url_query_params()) == len(request2.get_url_query_params())

    @staticmethod
    def match_two_traces(pairs1, pairs2):
        possible_matches = []
        for i in range(len(pairs1)):
            possible_matches.append([])
            for j in range(len(pairs2)):
                req2 = pairs2[j][0]
                if MatchingHelper.url_similar(pairs1[i][0], req2):
                    possible_matches[-1] += [j]

        def init_solver(length):
            solver = Solver()
            matched1 = IntVector("matched1", length)
            matched2 = IntVector("matched2", length)

            for i in range(length):
                solver.add(And(matched1[i] >= 0, matched1[i] < len(pairs1)))
                solver.add(And(matched2[i] >= 0, matched2[i] < len(pairs2)))

            for i in range(1, length):
                solver.add(matched1[i-1] < matched1[i])
                solver.add(matched2[i-1] < matched2[i])

            for i in range(length):
                for j in range(len(pairs1)):
                    solver.add(Implies(matched1[i] == j, Or([pm == matched2[i] for pm in possible_matches[j]])))

            return solver, matched1, matched2

        def add_model_constraint(solver, model, matched1, matched2, length):
            solver.add(Not(
                And(
                    And([matched1[i] == model[matched1[i]] for i in range(length)]),
                    And([matched2[i] == model[matched2[i]] for i in range(length)]),
                )
            ))

        def get_matching_from_model(model, matched1, matched2, length):
            matching = []
            for i in range(length):
                p1, p2 = model[matched1[i]].as_long(), model[matched2[i]].as_long()
                matching.append((pairs1[p1], pairs2[p2]))
            return matching

        max_length = min(len(pairs1), len(pairs2))
        for length in range(max_length, 0, -1):
            solver, matched1, matched2 = init_solver(length)
            while solver.check() == sat:
                m = solver.model()
                add_model_constraint(solver, m, matched1, matched2, length)
                yield get_matching_from_model(m, matched1, matched2, length)

    @staticmethod
    def match_urls(url1, url2):
        differences = []

        fragment1 = pa.parse_fragment_form_url(url1)
        fragment2 = pa.parse_fragment_form_url(url2)
        if fragment1 != fragment2:
            differences.append((fragment1, "fragment", None))

        query1 = pa.parse_query_from_url(url1)
        query2 = pa.parse_query_from_url(url2)
        for key in query1:
            try:
                if query1[key] != query2[key]:
                    differences.append((query1[key], "query", key))
            except KeyError:
                pass

        path_parts1 = pa.parse_path_from_url(url1)
        path_parts2 = pa.parse_path_from_url(url2)
        for i in range(len(path_parts1)):
            try:
                if path_parts1[i] != path_parts2[i]:
                    differences.append((path_parts1[i], "path", i))
            except IndexError:
                break

        return differences
