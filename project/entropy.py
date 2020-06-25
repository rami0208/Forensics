import sys
import math
import glob
import os
import re


# file_size: function returning a list containing the files' sizes of all the samples in the path
def associate_number_to_file(path):
    i = 0
    result = {}
    for file in glob.glob(os.path.join(path, '*')):
        file = file.split("/")[1]
        result[file] = i
        i += 1

    with open('file_numbers.csv', 'w') as f:
        f.write("%s,%s\n" % ("File Name", "File Number"))
        for key in result.keys():
            f.write("%s,%s\n" % (key, result[key]))
    return result


def file_size_direct(file):
    file_o = open(file, "rb")  # Open file
    file_o.seek(0, os.SEEK_END)  # Move file cursor to end
    return file_o.tell()


def file_size(path):
    print("[+] Calculating file sizes...")
    file_sizes = {}
    for file in glob.glob(os.path.join(path, '*')):
        size_direct = file_size_direct(file)
        file = file.split("/")[1]
        file_sizes[file] = size_direct

    file_numbers = associate_number_to_file(path)
    with open('sizes.csv', 'w') as f:
        f.write("%s,%s,%s\n" % ("File hash", "Size", "File Number"))
        for key in file_sizes.keys():
            f.write("%s,%s,%s\n" % (key, file_sizes[key], file_numbers[key]))

    return file_sizes


# entropy: function returning a list containing the files' entropies of all samples in the path

def entropy(path):
    print("[+] Calculating entropies...")
    list_entropies = {}
    for file in glob.glob(os.path.join(path, '*')):
        # For a specific file, create a frequency list of each byte in that file
        freqlist = []
        with open(file, 'rb') as f:
            array = list(f.read())
        for b in range(256):
            ctr = 0
            for byte in array:
                if byte == b:
                    ctr += 1
            freqlist.append(float(ctr) / file_size_direct(file))
        # Calculate shannon entropy
        entropy = 0
        for freq in freqlist:
            if freq > 0:
                entropy += freq * math.log(freq, 2)
        file = file.split("/")[1]
        list_entropies[file] = -entropy

    file_numbers = associate_number_to_file(path)

    with open('entropies.csv', 'w') as f:
        f.write("%s,%s,%s\n" % ("File Name", "Entropy", "File Number"))
        for key in list_entropies.keys():
            f.write("%s,%s,%s\n" % (key, list_entropies[key], file_numbers[key]))

    return list_entropies

