import json, sys, os, datetime
sys.path.append(r"C:\Users\Syuukakou\PycharmProjects\SCIS2022")
# from src.plotMethods import plot_dict_data
from src.common_functins import *
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import textwrap
import matplotlib
from pyvis.network import Network
import networkx as nx
from pprint import pprint


"""
4. 提取他们所使用的CVE 
    1. CVE和架构之间的关系图、统计图 
    2. 样本之间的CVE关系 -
       - 是不是又很多样本会共用同一个CVE，或者一个样本会使用多个CVE
"""

# rewrite  from plotMethods import plot_dict_data
def plot_dict_data(sources, save_path, title, xlabel, ylabel, fig_w, fig_h, rotation, show_Barlabel=False, wrap_xticklabels=False):
    """plot dict data

    Args:
        sources (dict): [description]
        save_path (file path): where the plotted file saved
        title (string): Plot image's title
        xlabel (string): x axis label
        ylabel (string): y axis label
        fig_w (int): figure size's width
        fig_h (int): figure size's height
        rotation (float or int): x axis tick label's rotation
        show_Barlabel (bool, optional): [Whether or not to show the value of the bar]. Defaults to False.
        wrap_xticklabels (bool, optional): [Whether or not to wrap the x axis tick labels]. Defaults to False.
    """

    x_data = list(sources.keys())
    y_data = list(sources.values())
    # seaborn
    # Width, height in inches
    plt.figure(figsize=(fig_w, fig_h))
    # sns.set_style("whitegrid")
    ax = sns.barplot(x=x_data, y=y_data)
    ax.set(xlabel=xlabel, ylabel=ylabel)
    ax.set_title(title)
    # plt.xticks(rotation=rotation)
    ax.set_xticklabels(x_data, rotation=rotation, ha='right')
    # plt.setp(ax.get_xticklabels(), rotation=rotation, rotation_mode="anchor", fontsize=10)
    # ax.tick_params(axis='x', which='major', pad=30)
    plt.ticklabel_format(style='plain', axis='y')
    ax.set_yticklabels(['{:,}'.format(int(x)) for x in ax.get_yticks().tolist()])
    # ax.tick_params(axis='x', rotation=rotation, labelsize=15, horizontalalignment="right")

    # 将x轴坐标label折叠
    if wrap_xticklabels:
        f = lambda x: textwrap.fill(x.get_text(), 10)
        ax.set_xticklabels(map(f, ax.get_xticklabels()))

    # add label
    if show_Barlabel:
        for p in ax.patches:
            ax.annotate("%.0f" % p.get_height(), (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                        textcoords='offset points', rotation=30)

    plt.tight_layout()
    plt.savefig(save_path)
    plt.show()

# Pyvis Networkx
def cve_relationship():
    hashes_archi = get_hashes_architecture()
    print(len(hashes_archi))
    cve_usage = get_CVE_Usage()
    archi_hashes = get_Architectures_hashes()
    
    cve_usages_NoneZero = {}
    for h in cve_usage:
        if len(cve_usage[h]) > 0:
            cve_usages_NoneZero[h] = cve_usage[h]
    
    archi_types = set()
    for h in hashes_archi:
        archi_types.add(hashes_archi[h])
    archi_types = list(archi_types)
    print(archi_types)
    archi_color = {
                    'sparc': "blue", 'amd': "orange", 'x86': "green", 'motorola': "red", 'mips': "purple", 
                    'i386': "brown", 'powerpc': "pink", 'aarch64': "gray", 'arm': "olive", 'superh': "cyan"}
    
    archi_graph = {}

    for archi in archi_hashes:
        if archi in archi_types:
            G = nx.Graph()
            for h in archi_hashes[archi]:
                if h in cve_usages_NoneZero:
                    G.add_node(h, color=archi_color[hashes_archi[h]])
                    for cve in cve_usages_NoneZero[h]:
                        G.add_node(cve, color="black")
                        G.add_edge(h, cve)
            archi_graph[archi] = G
            # net = Network('900px', '1800px')
            # net.from_nx(G)
            # net.show(r"files\resuls\\" + archi + "_CVE_Malware_Relationship.html")

    # Plot for Total Architectures
    TotalG = nx.Graph()
    for h in cve_usage:
        if len(cve_usage[h]) > 0:
            TotalG.add_node(h, color=archi_color[hashes_archi[h]])
            for cve in cve_usage[h]:
                TotalG.add_node(cve, color="black")
                TotalG.add_edge(h, cve)
    archi_graph["TotalArchi"] = TotalG
    # net = Network('900px', '1800px')
    # net.from_nx(TotalG)
    # net.show(r"files\resuls\All_Architectures_cve_malware_relationship.html")

    return archi_graph

def cve_usage_Statistics():
    with open(r"files\formatted_data\cve_usage.json", "r") as f:
        cve_usage = json.load(f)
    cves = []
    for h in cve_usage:
        cves.extend(cve_usage[h])
    cves_counts = dict(sorted(Counter(cves).items(), key=lambda item: item[1], reverse=True))
    # plot data
    plot_dict_data(cves_counts, r"files\resuls\Vulnerabilities Usage Statistics", "Statistics for Vulnerabilities Usage", "Vulnerabilities", "Counts", 20, 10, rotation=60, show_Barlabel=True, wrap_xticklabels=False)


def cve_architecture_Relationship():
    """
    Plot Relationship between Vulnerabilities and Architectures
    """
    archi_hashes = get_Architectures_hashes()
    cve_usage = get_CVE_Usage()
    total_cves = []
    for h in cve_usage:
        total_cves.extend(cve_usage[h])
    total_cves = list(set(total_cves))
    total_colors = list(matplotlib.colors.cnames.keys())
    colors = total_colors[:len(total_cves)]
    cve_color = {}
    for cve_name, color in zip(total_cves, colors):
        cve_color[cve_name] = color

    """
    x: archi - y: cve - point size: counts
    """
    data = []
    for archi in archi_hashes:
        cves = []
        for h in archi_hashes[archi]:
            if h in cve_usage:
                cves.extend(cve_usage[h])
        cves_counter = dict(Counter(cves))
        for cve_name, count in cves_counter.items():
            data.append([archi, cve_name, count, cve_color[cve_name]])
    pprint(data)
    
    Architectures = []
    CVE_names = []
    CVE_counts = []
    CVE_colorType = []
    for item in data:
        Architectures.append(item[0])
        CVE_names.append(item[1])
        CVE_counts.append(item[2]/5)
        CVE_colorType.append(item[3])
    plt.figure(figsize=(15, 15))
    plt.scatter(Architectures, CVE_names, s=CVE_counts, c=CVE_colorType)
    plt.xticks(fontsize=20, rotation=30)
    plt.yticks(fontsize=10)
    plt.tight_layout()
    plt.savefig(r"files\resuls\Relationship_Between_cve_architectures.png")
    plt.show()


if __name__ == "__main__":
    print(datetime.datetime.now())
    # graphs = cve_relationship()
    # print(len(graphs))
    # cve_usage_Statistics()
    cve_architecture_Relationship()