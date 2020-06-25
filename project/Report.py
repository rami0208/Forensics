from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.validators import Auto
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.pdfgen import canvas
from PIL import Image
from reportlab.graphics.charts.linecharts import VerticalLineChart
from reportlab.lib import colors
import matplotlib.pyplot as plt
import numpy as np
from entropy import file_size
from entropy import entropy
from plotly.graph_objs import *
import chart_studio.plotly as py


# Drawing the graph of sizes of samples, and saving it as a PNG file

def line_chart_sizes(results):
    data_sizes = results[0]
    files = results[2]
    x = files
    y = data_sizes
    xy_data = Scatter(x=x, y=y, mode='markers', name='AAPL')
    data = [xy_data]
    line_chart_size = py.plot(data, filename='apple stock moving average', auto_open=False)
    return line_chart_size


# Drawing the graph of entropies of samples, and saving it as a PNG file

def line_shart_entropies(results):
    data_entropies = results[1]
    print("generating plot of data entropies")
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.bar(np.arange(len(data_entropies)), data_entropies)
    plt.xlabel('Files')
    plt.ylabel('Entropies')
    plt.savefig('test2.png')
    return fig


# This function get the results of the scan of the different other functions

def get_results(Path):
    print("calculating entropy of samples...")
    # Calculate Entropy:
    list_of_entropies = entropy(Path)
    print("calculating sizes of samples...")
    # Calculate file sizes:
    list_of_sizes = file_size(Path)[0]
    list_of_files = file_size(Path)[1]

    return list_of_sizes, list_of_entropies, list_of_files


if __name__ == '__main__':
    results = get_results('test_set')
    print(results)
    Size_plot = line_chart_sizes(results)
    Entropy_plot = line_chart_sizes(results)


