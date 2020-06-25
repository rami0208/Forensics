from virus_total_apis import PublicApi as VirusTotalPublicApi
import hashlib
import json
import pefile
import requests
import yara
import os
import glob
import time
import csv
import jsondatetime
import re
from entropy import associate_number_to_file
import pandas as pd
import tlsh
import itertools
import sdhash


# Function that takes the path as input and returns the list of sha256 hashes of the files

def get_hash(path):
    # Access Virustotal API
    list_of_hashes = []
    # Calculate sha-256 hash of the file:
    for file in glob.glob(os.path.join(path, '*')):
        f = open(file, "rb")
        sha256_hash = hashlib.sha256()
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        hash_of_file = sha256_hash.hexdigest()
        list_of_hashes.append(hash_of_file)
    return list_of_hashes


# Return a dictionary containing (filename, imphash)

def getimphash(path):
    print("[+] Calculating imphashes...")
    result = {}
    for file in glob.glob(os.path.join(path, '*')):
        try:
            PE_version_of_file = pefile.PE(file)
            imphash = PE_version_of_file.get_imphash()
            result[file] = imphash
            with open('Imphash.csv', 'w') as f:
                f.write("%s,%s\n" % ("File path", "Imphash"))
                for key in result.keys():
                    f.write("%s,%s\n" % (key, result[key]))
        except:
            print("Impossible to get imphash since the files is not a PE")


# Function extracting information from virustotal, and writing it under CSV files

def get_report(path):
    list_of_hashes = get_hash(path)
    apiurl = "https://www.virustotal.com/api/v3/"
    API_KEY = '2a11b9bed44b9580bde1033624b38d32fad0c470a8611dc5928ee8d85060745a'
    vhashes = {}
    Dates_of_first_seen = {}
    Compilation_time = {}
    count = 0
    votes = {}
    last_analysis_result = {}
    number = 0
    print("[+] Getting the report from Virus Total...")
    for hash in list_of_hashes:
        try:
            headers = {'x-apikey': API_KEY}
            response = requests.get(apiurl + 'files/' + hash, headers=headers)
            response_json = response.json()

            if 'vhash' in response_json['data']['attributes']:
                vhash = response_json['data']['attributes']['vhash'].encode("ascii")
                vhashes[hash] = vhash

            first_seen = time.gmtime(response_json['data']['attributes']['first_submission_date'])
            first_seen_formatted = time.strftime('%Y-%m-%dT%H:%M:%SZ', first_seen)
            Dates_of_first_seen[hash] = first_seen_formatted

            try:
                compiltime = time.gmtime(response_json['data']['attributes']['pe_info']['timestamp'])
                Compilation_time[hash] = time.strftime('%Y-%m-%dT%H:%M:%SZ', compiltime)

            except:
                Compilation_time[hash] = "Not found"

            vote = response_json['data']['attributes']['last_analysis_stats']
            votes[hash] = vote

            dict_result = {}
            dict_result['McAfee'] = response_json['data']['attributes']['last_analysis_results']['McAfee']['result']
            dict_result['Bitdefender'] = response_json['data']['attributes']['last_analysis_results']['BitDefender'][
                'result']
            dict_result['AVIRA'] = response_json['data']['attributes']['last_analysis_results']['Avira']['result']
            dict_result['Avast'] = response_json['data']['attributes']['last_analysis_results']['Avast']['result']
            dict_result['Symantec'] = response_json['data']['attributes']['last_analysis_results']['Symantec']['result']
            dict_result['eset'] = response_json['data']['attributes']['last_analysis_results']['ESET-NOD32']['result']
            dict_result['AVG'] = response_json['data']['attributes']['last_analysis_results']['AVG']['result']
            dict_result['Kaspersky'] = response_json['data']['attributes']['last_analysis_results']['Kaspersky'][
                'result']
            dict_result['Malwarebytes'] = response_json['data']['attributes']['last_analysis_results']['Malwarebytes'][
                'result']
            dict_result['TotalDefense'] = response_json['data']['attributes']['last_analysis_results']['TotalDefense'][
                'result']

            last_analysis_result[hash] = dict_result

            count += 1
            number +=1
            print(f'Sample number {number} analysed using VT')
            if count == 4 and number != 100:
                print("[-] SLEEPING...")
                time.sleep(60)
                count = 0
        except:
            print('Error')

    print("[+] Virus Total results extracted successfully")
    with open('vhashes.csv', 'w') as f:
        f.write("%s,%s\n" % ("File hash", "Vhash"))
        for key in vhashes.keys():
            f.write("%s,%s\n" % (key, vhashes[key]))

    with open('datefirstseen.csv', 'w') as f:
        f.write("%s,%s\n" % ("File hash", "Date of first seen"))
        for key in Dates_of_first_seen.keys():
            f.write("%s,%s\n" % (key, Dates_of_first_seen[key]))

    with open('Timestamps.csv', 'w') as f:
        f.write("%s,%s\n" % ("File hash", "Compilation Time"))
        for key in Compilation_time.keys():
            f.write("%s,%s\n" % (key, Compilation_time[key]))

    with open('votes.csv', 'w') as f:
        f.write("%s,%s,%s,%s,%s,%s,%s,%s\n" % (
            "File hash", "Confirmed-Timeout", "Failure", "Harmless", "Malicious", "Suspicious", "Type-unsupported",
            "Undetected"))
        for key in votes.keys():
            subkey = votes[key]
            f.write("%s,%s,%s,%s,%s,%s,%s,%s\n" % (
                key, subkey['confirmed-timeout'], subkey['failure'], subkey['harmless'], subkey['malicious'],
                subkey['suspicious'], subkey['type-unsupported'], subkey['undetected']))

    with open('antivirusresults.csv', 'w') as f:
        f.write("%s,%s,%s,%s,%s,%s,%s,%s\n" % (
            "File hash", "McAfee", "Bitdefender", "AVIRA", "Avast", "Symantec", "ESET", "AVG"))
        for key in last_analysis_result.keys():
            subkey = last_analysis_result[key]
            f.write("%s,%s,%s,%s,%s,%s,%s,%s\n" % (
                key, subkey['McAfee'], subkey['Bitdefender'], subkey['AVIRA'], subkey['Avast'], subkey['Symantec'],
                subkey['eset'], subkey['AVG']))


# ssdeep: return a dictionary containing all the file names and all the ssdeep fuzzy hashes of those files:
# ssdeep package need to be installed on terminal

def ssdeep(path):
    stream = os.popen("ssdeep -brd -a " + path)
    output_ssdeep = stream.read()
    return output_ssdeep.splitlines()


# Function creating table of matches according to the result of ssdeep hashes

def create_table_of_matches(path):
    print ("[+] Creating ssdeep matches")
    list_results = ssdeep(path)
    result = []
    with open('file_numbers.csv', mode='r') as infile:
        reader = csv.reader(infile)
        mydict = {rows[0]: rows[1] for rows in reader}

    for element in list_results:
        splitted_element = element.split()
        splitted_element[3] = re.sub('[()]', '', splitted_element[3])
        result.append(
            [splitted_element[0], mydict[splitted_element[0]], splitted_element[2], mydict[splitted_element[2]],
             splitted_element[3]])

    with open("matches.csv", "w", newline="") as f:
        writer = csv.writer(f)
        result.insert(0, ["File 1", "File 1 Number", "File 2", "File 2 Number", "Score"])
        writer.writerows(result)

    return result


def tlshh(path):
    print("[+] Creating tlsh matches")
    result = []
    with open('file_numbers.csv', mode='r') as infile:
        reader = csv.reader(infile)
        mydict = {rows[0]: rows[1] for rows in reader}

    for pair in itertools.combinations(glob.glob(os.path.join(path, '*')), r = 2):
        file1 = pair[0]
        file2 = pair[1]
        filename1 = file1.split("/")[1]
        filename2 = file2.split("/")[1]
        h1 = tlsh.hash(open(file1, 'rb').read())
        h1_number = mydict[filename1]
        h2 = tlsh.hash(open(file2, 'rb').read())
        h2_number = mydict[filename2]
        score = tlsh.diff(h1, h2)
        result.append([h1_number, h1, h2_number, h2, 1000-score])

    with open("matchestlsh.csv", "w", newline="") as f:
        writer = csv.writer(f)
        result.insert(0, ["File 1 Number", "File 1 Hash", "File 2 Number", "File 2 Hash", "Score"])
        writer.writerows(result)


