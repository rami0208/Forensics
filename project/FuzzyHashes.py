import pandas as pd
from collections import Counter
import csv
import operator
import matplotlib.pyplot as plt
from YARA import *

# Create the tables that will be put in the report as sublinks:

def usefulfunction(element):
    element = element.split("/")[1]
    return element

# Table of numbers from csv
def table_of_numbers():
    df = pd.read_csv("file_numbers.csv")
    html_numbers = df.to_html()
    Html_file = open("html_file_numbers.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()


# Create table of first_seen from csv
def table_of_first_seen():
    df = pd.read_csv("datefirstseen.csv")
    html_numbers = df.to_html()
    Html_file = open("firstseen.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()

def table_of_ssdeep():
    df = pd.read_csv("matches.csv")
    html_numbers = df.to_html()
    Html_file = open("ssdeep.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()

def table_of_results():
    df = pd.read_csv("antivirusresults.csv")
    html_numbers = df.to_html()
    Html_file = open("avresults.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()

def table_of_matches():
    df = pd.read_csv("votes.csv")
    html_numbers = df.to_html()
    Html_file = open("matches.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()

def table_of_vhashes():
    df = pd.read_csv("vhashes.csv")
    html_numbers = df.to_html()
    Html_file = open("vhashes.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()

def table_of_Imphashes():
    df = pd.read_csv("Imphash.csv")
    html_numbers = df.to_html()
    Html_file = open("Imphashes.html", "w")
    Html_file.write(html_numbers)
    Html_file.close()

    df_grouped = df.groupby("Imphash").size()
    df_grouped.to_csv("new.csv")


def table_of_unique():
    dataframe = pd.read_csv("antivirusresults.csv")
    values = dataframe.values
    results = []
    for liste in values:
        new_unique_liste = list(set(liste[1:]))  # Removes the first element of each list (file hash) and keep only unique elements, so that if two AVs give the same label, it won't be counted twice.
        for element in new_unique_liste:
            results.append(element)
    counter = Counter(results)
    # registering how many unique values do we have:
    unique_values = open("fileupload", "w")
    unique_values.write(str(len(counter)))
    unique_values.close()

    # registering the counter into csv:
    with open('unique.csv', 'w') as csvfile:
        fieldnames = ['label', 'number']
        writer = csv.writer(csvfile)
        writer.writerow(fieldnames)
        for key, value in counter.most_common(10):
            csvfile.write("%s,%s\n" % (key, value))


def table_of_tlsh():
    dataframe = pd.read_csv("matchestlsh.csv")
    tlshmatches = dataframe.to_html()
    Html_file = open("tlsh.html", "w")
    Html_file.write(tlshmatches)
    Html_file.close()


def table_of_yara(file, rules):
    yara_dict = match_yara(file, rules)
    with open('yara.csv', 'w') as f:
        f.write("%s,%s\n" % ("File", "Matched rule(s)"))
        if yara_dict is not None: 
            for key in yara_dict.keys():
                keyname = key.split("/")[1]
                f.write("%s,%s\n" % (keyname, yara_dict[key]))
                value = yara_dict[key].split("/")[1]
                f.write("%s,%s\n" % (keyname, value))


def tableyara():
    dataframe = pd.read_csv("yara.csv")
    bl = dataframe.empty
    if not bl: # if the dataframe is not empty, we create a html page having the matched yara rules
        yara = dataframe.to_html()
        Html_file = open("yara.html", "w")
        Html_file.write(yara)
        Html_file.close()
    else: # Else, we create a html table saying : no matched yara rules
        Html_file = open("yara.html", "w")
        message = """<html>
        <head></head>
        <body><p>No matched yara rules</p></body>
        </html>"""
        Html_file.write(message)
        Html_file.close()



