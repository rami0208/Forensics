from HTML import *
from virustotal import *
from entropy import *
from FuzzyHashes import *
import sys, getopt
import argparse
from YARA import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("Input", help="Please give the input folder containing the samples")
    parser.add_argument("--output", dest="output_file", help="Please give the name of the output HTML file")
    parser.add_argument("--name", dest="family_name",
                        help="Please give the family name of the samples to get the resources available on this family")
    args = parser.parse_args()
    print(args)
    input = args.Input
    output_file = args.output_file
    family_name = args.family_name

    # Generating file numbers and writing to CSV:
    associate_number_to_file(input)
    # Generating file sizes and writing to CSV:
    file_size(input)

    # Generating entropies and writing to CSV:
    entropy(input)

    # Generating Virus Total results and writing to CSV:
    get_report(input)

    # Generating ssdeep and tlsh results and writing to CSV:
    create_table_of_matches(input)
    tlshh(input)

    # Generating imphashes and writing to CSV:
    getimphash(input)

    # Sign in to plot results:
    sign_in()

    # Delete old graphs, to free space in plotly:
    delete_old()

    # Creating html tables for results:
    table_of_numbers()
    table_of_first_seen()
    table_of_ssdeep()
    table_of_results()
    table_of_matches()
    table_of_vhashes()
    table_of_Imphashes()
    table_of_unique()
    table_of_tlsh()

    # Create html table for yara rules

    RULES_DIR = "malware/"
    FILES_DIR = input
    table_of_yara(RULES_DIR, FILES_DIR)
    tableyara()

    # Plotting results
    sizes = plot_sizes()
    entropies = plot_entropies()
    plot_matches_tlsh_ssdeep()  # writing to png file
    table_of_unique()
    AVs = plot_AVs()
    dates_of_first_seen = plot_dates_of_first()
    compilation_times = plot_compilation_times()
    number_votes = plot_number_votes()
    imphashes = plot_imphashes()
    resources = get_resources_html()

    create_html(output_file, family_name, sizes, entropies, dates_of_first_seen, AVs, compilation_times,
                number_votes, imphashes, resources)


if __name__ == "__main__":
    main()
