#  Matching predefined YARA rules for malware:

import glob
import os
import yara
from typing import Generator

RULES_DIR = "malware/"  # Directory containing this file.
FILES_DIR = "upatre/"


def match_yara(RULES_DIR, FILES_DIR):
    print("[+] Matching Yara rules...")
    result = {}
    for file in glob.glob(os.path.join(FILES_DIR, '*')):  # for each file in samples
        rules_matched = []
        for rule in glob.glob(os.path.join(RULES_DIR, '*')):
            stream = os.popen("yara -r -w -c -s " + rule + " " + file)
            output_yara = stream.read()
            int_output = int(output_yara)
            if int_output != 0:
                rules_matched.append(rule)
        if rules_matched:
            result[file] = rules_matched
    if result:
        print("[+] Yara rules successfully matched for this family")
        return result
    else:
        print("[-] No yara rules matched for this malware family")






