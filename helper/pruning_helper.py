import mime_types.mime_types as mt
from helper.utils import *
from config import USE_ORACLE, CUSTOM_FILTER, CONFIGURATION


class PruningHelper:
    mime_types = mt.load("./mime_types")

    @staticmethod
    def get_prunable_codes_and_extenstions():
        whitelist = [("json", "application/json"), ("xml", "application/xml"), ("html", "text/html"), ("xml", "text/xml")]
        extensions_to_prune = ["js", "js", "es", "esm", "ico"]
        codes_to_prune = ["application/javascript", "application/x-javascript", "application/ecmascript", "application/x-ecmascript", "vnd.microsoft.icon"]
        for media_type in ["image", "video", "audio", "font", "model", "text", "application"]:
            extensions_to_prune += PruningHelper.mime_types[media_type]["extensions"]
            codes_to_prune += PruningHelper.mime_types[media_type]["codes"]

        extensions_to_prune = [ext.lower() for ext in extensions_to_prune]
        codes_to_prune = [code.lower() for code in codes_to_prune]

        for extension, code in whitelist:
            if extension in extensions_to_prune:
                extensions_to_prune.remove(extension)
            if code in codes_to_prune:
                codes_to_prune.remove(code)

        return extensions_to_prune, codes_to_prune

    @staticmethod
    def prune_by_type(http_pairs):
        print("Pruning by type...")
        pruned_pairs = []

        extensions_to_prune, codes_to_prune = PruningHelper.get_prunable_codes_and_extenstions()

        fe_prune_count = 0
        ct_prune_count = 0
        sfd_prune_count = 0

        # only sec-fetch-data
        # only content-type
        # only file-ext
        # sec-fetch-data + content-type
        # sec-fetch-data + file-ext
        # content-type + file-ext
        # all three
        counts = {
            "sec-fetch-data-only": 0,
            "content-type-only": 0,
            "file-extension-only": 0,
            "sec-content": 0,
            "sec-ext": 0,
            "content-ext": 0,
            "all": 0
        }

        for req, res in http_pairs:
            sec_fetch = False
            content_type = False
            file_ext = False

            # checking file extension
            if ends_with_any(req.url.lower(), extensions_to_prune):
                fe_prune_count += 1
                file_ext = True

            # checking fetch metadata header
            if "sec-fetch-dest" in req.headers:
                sfd = req.headers["sec-fetch-dest"]
                if sfd.lower() not in ["", "document", "empty"]:
                    sfd_prune_count += 1
                    sec_fetch = True

            # checking content-type
            if "content-type" in res.headers:
                content_type_string = res.headers["content-type"].split(";")[0]
                if content_type_string.lower() in codes_to_prune:
                    ct_prune_count += 1
                    content_type = True

            if sec_fetch and content_type and file_ext:
                counts["all"] += 1
            elif sec_fetch and content_type:
                counts["sec-content"] += 1
            elif sec_fetch and file_ext:
                counts["sec-ext"] += 1
            elif content_type and file_ext:
                counts["content-ext"] += 1
            elif sec_fetch:
                counts["sec-fetch-data-only"] += 1
            elif content_type:
                counts["content-type-only"] += 1
            elif file_ext:
                counts["file-extension-only"] += 1
            else:
                pruned_pairs.append((req, res))

        if CONFIGURATION["DEBUG"]:
            print("\tPruned:")
            print("\t\tSec-Fetch-Dest header only: %d" % counts["sec-fetch-data-only"])
            print("\t\tContent-Type header only: %d" % counts["content-type-only"])
            print("\t\tFile extension only: %d" % counts["file-extension-only"])
            print("\t\tSec-Fetch-Dest and Content-Type overlap: %d" % counts["sec-content"])
            print("\t\tSec-Fetch-Dest and File extension overlap: %d" % counts["sec-ext"])
            print("\t\tContent-Type and File extension overlap: %d" % counts["content-ext"])
            print("\t\tAll three overlap: %d" % counts["all"])

        return pruned_pairs

    @staticmethod
    def prune_by_custom_filter(http_pairs):
        return [pair for pair in http_pairs if not CUSTOM_FILTER(pair)]

    @staticmethod
    def prune_http_pairs_statically(http_pairs):
        print("Statically pruning:")
        pairs = PruningHelper.prune_by_type(http_pairs)
        pairs = PruningHelper.prune_by_custom_filter(pairs)
        return pairs

    @staticmethod
    def prune_by_oracle(http_pairs):
        pruned = http_pairs[:]

        while len(pruned) > 0 and not USE_ORACLE(pruned[-1]):
            pruned = pruned[:-1]

        return pruned
