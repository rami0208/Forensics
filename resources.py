from googlesearch import search


def get_resources(name_of_family):
    result = []
    for link in search(name_of_family+"malware", stop=3):
        result.append(link)
    return result



