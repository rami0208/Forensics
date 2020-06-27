# Forensics
The goal of this project is to write a set of tools that take a number of samples that belong the same family, make an analysis on these samples and generate a number of plots that are displayed in a report page (HTML). 

The report generated contains the following information: 
* Size
* Entropy
* Different similarity hashes (ssdeep, tlsh)
* Virustotal vhashes
* Samples compilation times
* Dates of first seen in the wild
* Imphashes
* Number of matches on virustotal 
* AV label consistency
* Links to online resources available on the family 
* Matching yara rules using a set of predefined yara rules

In order to use this tool, we need to install these dependencies: 
```bash
pip3 install -r requirements.txt
```
Then we need to install useful modules for Linux:
* Yara from: https://yara.readthedocs.io/en/stable/gettingstarted.html
* Ssdeep by doing: 
```bash
sudo apt-get install ssdeep
```

In case of problems, please refer to the troubleshooting section. 


We can check the help section of the tool with: 
```bash
Python3 Main.py [name of input samples] -h 
```
Here is the help section: 

![Image of help section](help_section.png)

We need to put the input samples folder in the same directory as the tool, then we can launch the tool, for example, by doing: 
```bash
Python3 Main.py upatre --output Report.html --name upatre
```
If the dependencies are correcly installed, we can get: 

![Image of first part of result](1.png)

Then, after all the samples are analyzed with virustotal, we can get: 

![Image of first part of result](2.png)

A file named "Report.html" is created in the same directory with the analysis of the samples. 
