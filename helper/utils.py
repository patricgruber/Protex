def ends_with_any(string, stringlist):
    for end_str in stringlist:
        if string.endswith(end_str):
            return True
    return False
