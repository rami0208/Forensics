import plotly as pyl
import pandas as pd
import numpy as np
import operator
from datetime import datetime
from datetime import time as dt_tm
from datetime import date as dt_date
import chart_studio.plotly as py
import plotly.tools as plotly_tools
from plotly.graph_objs import *
import os
import tempfile
import plotly.graph_objects as go
import seaborn as sns
import matplotlib.pyplot as plt
import requests
import chart_studio
import json

os.environ['MPLCONFIGDIR'] = tempfile.mkdtemp()
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde
from IPython.display import HTML
from resources import get_resources
from requests.auth import HTTPBasicAuth


def sign_in():
    # Sign in Plotly
    py.sign_in("rami002", "tgBBrvotx5v3BikEbJAz")


def plot_sizes():
    # Plotting sizes
    print("[+] Plotting sizes...")
    df = pd.read_csv('sizes.csv')
    y = df['Size']
    x = df['File Number']
    xy_data = Bar(x=x, y=y)
    data = [xy_data]
    Sizes = py.plot(data, auto_open=False, )
    return Sizes


def plot_entropies():
    # Plotting Entropies
    print("[+] Plotting entropies...")
    df = pd.read_csv('entropies.csv')
    y = df['Entropy']
    x = df['File Number']
    xy_data = Bar(x=x, y=y)
    data = [xy_data]
    Entropies = py.plot(data, auto_open=False, )
    return Entropies


def plot_matches_tlsh_ssdeep():
    # Plotting matches according to TLSH and SSDEEP:
    print("[+] Plotting matches according to TLSH...")
    df2 = pd.read_csv('matchestlsh.csv')
    df = pd.read_csv('matches.csv')
    fig, ax = plt.subplots(1, 2, figsize=(14, 12))
    ax[0].set_title("Distribution of matches according to SSDEEP")
    ax[1].set_title("Distribution of matches according to TLSH")
    sns.heatmap(df.pivot(index='File 1 Number', columns='File 2 Number', values='Score'), ax=ax[0], cmap="YlGnBu")
    sns.heatmap(df2.pivot(index='File 1 Number', columns='File 2 Number', values='Score'), ax=ax[1], cmap="YlGnBu")
    fig.savefig("subplot.png")


def plot_AVs():
    # Plotting results of the best AVs:
    print("[+] Plotting results of the best AVs...")
    counter = pd.read_csv('unique.csv')
    labels = counter['label']
    values = counter['number']
    pie = Pie(labels=labels, values=values)
    uniq = py.plot([pie], auto_open=False, )
    return uniq


def plot_dates_of_first():
    # Plotting dates of first seen:
    print("[+] Plotting dates of first seen...")
    df = pd.read_csv('datefirstseen.csv')
    other = pd.read_csv('file_numbers.csv')
    new = df.set_index('File hash').join(other.set_index('File Name'))
    y = new['Date of first seen']
    x = new['File Number']
    xy_data = Scatter(x=x, y=y, mode='markers')
    Date_of_first_seen = py.plot([xy_data], auto_open=False, )
    return Date_of_first_seen


def plot_compilation_times():
    # Plotting compilation times:
    print("[+] Plotting compilation times...")
    df = pd.read_csv('Timestamps.csv')
    other = pd.read_csv('file_numbers.csv')
    new = df.set_index('File hash').join(other.set_index('File Name'))
    y = new['Compilation Time']
    x = new['File Number']
    xy_data = Scatter(x=x, y=y, mode='markers')
    TimeStamp = py.plot([xy_data], auto_open=False, )
    return TimeStamp


def plot_number_votes():
    # Plotting number of votes:
    df = pd.read_csv('votes.csv')
    other = pd.read_csv('file_numbers.csv')
    new = df.set_index('File hash').join(other.set_index('File Name'))
    y = new['Malicious']
    x = new['File Number']
    xy_data = Bar(x=x, y=y)
    data = [xy_data]
    Numberofmatches = py.plot(data, auto_open=False, )
    return Numberofmatches


def plot_imphashes():
    # Plotting Imphashes
    print("[+] Plotting Imphashes...")
    with open('fileupload', 'r') as f:
        value = f.read()

    counter = pd.read_csv('new.csv')
    labels = counter['Imphash']
    values = counter['0']
    new_labels = []
    new_values = []
    for i in range(len(labels)):
        if values[i] > 1:
            new_labels.append(labels[i])
            new_values.append(values[i])
        else:
            new_labels.append("Other Imphashes")
            new_values.append(1)
    pie = Pie(labels=new_labels, values=new_values)
    uniq2 = py.plot([pie], auto_open=False, )
    return uniq2


def get_resources_html():
    # Getting the resources concerning the family:
    name_of_family = 'upatre'
    list_of_links = get_resources(name_of_family)
    string = "<ul>\n"
    for s in list_of_links:
        string += "<li>" + "<a href=\"" + str(s) + "\">" + str(s) + "</a>\n" + "</li>"

    return string + "\n</ul>"


def create_html(output_file_name, family_name, sizes, entropies, dates_of_first_seen, AVs, compilation_times, number_votes, imphashes, resources):
    # Creating HTML:
    print("[+] Creating HTML...")
    html_string = '''
    <html>
        <head>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
            <style>body{ margin:0 100; background:whitesmoke; }</style>
        </head>
        <body>
            <h1> Report for analysing the list of samples belonging to the family: ''' + family_name + '''</h1>
            <p>To analyze the list of samples, we have associated a number to each file, please refer to this table to find which file is associated to which number</p>
            <button onclick="document.location = 'html_file_numbers.html'">Files and numbers association</button>
            <!-- *** Section 1 *** --->
            <h2>1- Distribution of sizes</h2>
            <iframe width="900" height="600" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + sizes + '''.embed?width=800&height=600"></iframe>
    
    
              <!-- *** Section 2 *** --->
            <h2>2- Distribution of entropies</h2>
            <iframe width="900" height="600" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + entropies + '''.embed?width=800&height=600"></iframe>
    
    
            <!-- *** Section 3 *** --->
            <h2>3- Distribution of dates of first seen</h2>
            <iframe width="900" height="600" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + dates_of_first_seen + '''.embed?width=800&height=600"></iframe>
            <p> Here you can find the table associating each file to its table of first seen </p>
             <button onclick="document.location = 'firstseen.html'">Date of first seen</button>
    
            <!-- *** Section 4 *** --->
            <h2>4- Distribution of matches according to SSDEEP and TLSH</h2>
            <p>
                <img src = "subplot.png"
                alt = "Heatmap" />
             </p>
             
             <p> Here you can find the table associating file names and numbers with the ssdeep scores </p>
             <button onclick="document.location = 'ssdeep.html'">SSDEEP scores</button>
             
             <p> Here you can find the table associating file names and numbers with the TLSH scores </p>
             <button onclick="document.location = 'tlsh.html'">TLSH scores</button>
             
             
             <!-- *** Section 5 *** --->
             <h2>5- Results of the best AVs</h2>
              <p>  We can plot the number of samples of the most frequent labels we have encountered: </p>  
             <iframe width="900" height="600" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + AVs + '''.embed?width=800&height=600"></iframe>
             <p> Here you can find the results of the best AVs</p>
             <button onclick="document.location = 'avresults.html'">AV results</button>
             
              <!-- *** Section 6 *** --->
              <h2>6- Samples compilation Time</h2>
              <iframe width="900" height="600" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + compilation_times + '''.embed?width=800&height=600"></iframe>
    
              <!-- *** Section 7 *** --->
              <h2>7- Number of matches</h2>
              <iframe width="900" height="600" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + number_votes + '''.embed?width=800&height=600"></iframe>
              <p> Here you can find the detailed results about the matches</p>
              <button onclick="document.location = 'matches.html'">AV results</button>
              
              
              <!-- *** Section 8 *** --->
              <h2>8- Table of Vhashes</h2>
              <p> Here you can find the table associating each file to its Vhash</p>
              <button onclick="document.location = 'vhashes.html'">Vhashes</button>
              
              <!-- *** Section 9*** --->
              <h2>9- Table of Imphashes</h2>
              <p> Most found Imphashes</p>
              <iframe width="900" height="800" frameborder="0" seamless="seamless" scrolling="no" \
    src="''' + imphashes + '''.embed?width=800&height=800"></iframe>
              <p> Here you can find the table associating each file to its Imphash</p>
              <button onclick="document.location = 'Imphashes.html'">Impashes</button>
              
               <!-- *** Section 10*** --->
              <h2>10- Matching YARA rules</h2>
              <p> Here you can find the table associating each file to its matched YARA rules</p>
                <button onclick="document.location = 'yara.html'">Matched YARA rules</button>

              
              <!-- *** Section 11*** --->
              <h2>11- Best resources available on this family</h2> ''' + resources + '''
               
        </body>
    </html>'''

    f = open(output_file_name, 'w')
    f.write(html_string)
    f.close()


def get_pages(username, auth, headers, page_size):
    url = 'https://api.plot.ly/v2/folders/all?user='+username+'&page_size='+str(page_size)
    response = requests.get(url, auth=auth, headers=headers)
    if response.status_code != 200:
        return
    page = json.loads(response.content)
    yield page
    while True:
        resource = page['children']['next']
        if not resource:
            break
        response = requests.get(resource, auth=auth, headers=headers)
        if response.status_code != 200:
            break
        page = json.loads(response.content)
        yield page


def permanently_delete_files(username, auth, headers, page_size=500, filetype_to_delete='plot'):
    for page in get_pages(username, auth, headers, page_size):
        for x in range(0, len(page['children']['results'])):
            fid = page['children']['results'][x]['fid']
            res = requests.get('https://api.plot.ly/v2/files/' + fid, auth=auth, headers=headers)
            res.raise_for_status()
            if res.status_code == 200:
                json_res = json.loads(res.content)
                if json_res['filetype'] == filetype_to_delete:
                    # move to trash
                    requests.post('https://api.plot.ly/v2/files/'+fid+'/trash', auth=auth, headers=headers)
                    # permanently delete
                    requests.delete('https://api.plot.ly/v2/files/'+fid+'/permanent_delete', auth=auth, headers=headers)


def delete_old():
    username = 'rami002' # Replace with YOUR USERNAME
    api_key = 'tgBBrvotx5v3BikEbJAz' # Replace with YOUR API KEY
    auth = HTTPBasicAuth(username, api_key)
    headers = {'Plotly-Client-Platform': 'python'}

    chart_studio.tools.set_credentials_file(username=username, api_key=api_key)

    permanently_delete_files(username, auth, headers, filetype_to_delete='plot')
    permanently_delete_files(username, auth, headers,  filetype_to_delete='grid')

