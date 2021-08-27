import os
import pickle
import csv


def create(directory="."):
    mime_types = {}

    for file in os.listdir(directory+"/"):
        if file.endswith(".csv"):
            with open(directory+"/"+file, "r") as csv_file:
                parsed_lines = csv.reader(csv_file)
                lines = [line[:2] for line in parsed_lines][1:]

            file_type = file[:-4]
            mime_types[file_type] = {}

            codes = []
            extensions = []
            for line in lines:
                ext = line[0]
                code = line[1]
                if code == "":
                    code = type+"/"+ext
                extensions.append(ext)
                codes.append(code)

            mime_types[type]["extensions"] = extensions
            mime_types[type]["codes"] = codes

    pickle.dump(mime_types, open(directory+"/mime_types.pkl", "wb"))


def load(directory="."):
    return pickle.load(open(directory+"/mime_types.pkl", "rb"))
