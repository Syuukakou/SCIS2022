import os, json, sys
from collections import Counter
from typing import OrderedDict
from plotMethods import plot_dict_data
sys.path.append(r"C:\Users\Syuukakou\PycharmProjects\SCIS2022")
import matplotlib.pyplot as plt



def format_data():
    """
    1. 提取52617个样本的哈希值 --> hash2fcns
    2. 提取他们的架构信息 --> archiPerFile, archi2hash
    3. 提取他们的opcode和function call: --> opcodes, fcns
    """
    opcodes = {}
    fcns = {}
    with open(r"files\source_data\52617_hash2fcns.json", "r") as f:
        hash2fcns = json.load(f)
    with open(r"files\source_data\allFinal_opcodes.json", "r") as f:
        total_opcodes = json.load(f)
    with open(r"files\source_data\allFinal_fcns.json", "r") as f:
        total_fcns = json.load(f)
    with open(r"files\source_data\allFinal_architectures_hashcodes.json", "r") as f:
        total_Archi2Hash = json.load(f)

    
    for h in hash2fcns:
        if h in total_opcodes:
            opcodes[h] = total_opcodes[h]
        if h in total_fcns:
            fcns[h] = total_fcns[h]
    
    architectures = list(total_Archi2Hash.keys())
    archi2hash = {i:[] for i in architectures}
    for h in hash2fcns:
        for archi in total_Archi2Hash:
            if h in total_Archi2Hash[archi]:
                archi2hash[archi].append(h)
    hashes = []
    archiPerFile = {}
    for archi in archi2hash:
        hashes.extend(archi2hash[archi])
        for h in archi2hash[archi]:
            archiPerFile[h] = archi

def plot_ArchitectureStatistics():
    with open(r"files\formatted_data\architectures_hashcodes_dict.json", "r") as f:
        data = json.load(f)
    plot_data = {}
    for archi in data:
        if len(data[archi]) > 0:
            plot_data[archi] = len(data[archi])
    
    # sort plot_data
    plot_data = dict(sorted(plot_data.items(), key=lambda item: item[1], reverse=True))
    # plot data
    plot_dict_data(plot_data, r"files\resuls\architectures Statistics.png", "Architectures Statisitcs", "Architectures", "The Number of Samples", 10, 8, 30, show_Barlabel=True)

"""
Opcodes
"""

def plot_Top_opcodes_Statistics():
    with open(r"files\formatted_data\totalOpcodes_Counts.json", "r") as f:
        totalOpcodes_Counts = json.load(f)
    # Total opcodes Statistics --> Top 100
    top100_opcodes = list(totalOpcodes_Counts.keys())[:50]
    total_opcodes_plot_data = {i:0 for i in top100_opcodes}
    for op in top100_opcodes:
        total_opcodes_plot_data[op] = totalOpcodes_Counts[op]
    plot_dict_data(total_opcodes_plot_data, r"files\resuls\Top 50 Used Frequently Opcodes Statistics.png", 
            "Statistics for Top 50 Frequently Used Opcodes", "Opcodes", "The Number of Opcode", 15, 8, 30, show_Barlabel=False)

def plot_opcodesPer_Architecures():
    with open(r"files\formatted_data\architectures_opcodes.json", "r") as f:
        archi_opocdes = json.load(f)
    
    archi_types = list(archi_opocdes.keys())
    archi_Top10_opcodes = {i: [] for i in archi_types}

    for archi in archi_opocdes:
        top10_names = list(archi_opocdes[archi].keys())[:50]
        top10_opcodes = {}
        for op in top10_names:
            top10_opcodes[op] = archi_opocdes[archi][op]
        archi_Top10_opcodes[archi] = top10_opcodes
    print(archi_Top10_opcodes)
    plot_data = {}
    count = 0
    for archi in archi_Top10_opcodes:
        plot_data[count] = {
            "opcode_names": list(archi_Top10_opcodes[archi].keys()),
            "opcode_counts": list(archi_Top10_opcodes[archi].values()),
            "architecture": archi
        }
        count += 1

    # plot
    fig, axes = plt.subplots(2, int(len(archi_Top10_opcodes)/2), figsize=(30, 15))
    fig.suptitle("Top 50 Frequently Used Opcodes for Each Architecture", x=0.5, y=0.998, fontsize=25)
    for i, ax in enumerate(axes.flatten()):
        if i in plot_data:
            ax.bar(plot_data[i]["opcode_names"], plot_data[i]["opcode_counts"])
            ax.set_title(plot_data[i]["architecture"])
            ax.tick_params('x', labelrotation=90, labelsize=8)
            ax.margins(x=0)
    plt.tight_layout()
    plt.savefig(r"files\resuls\opcodes Statistics on Each Architecture.png", dpi=300)
    # plt.show()

"""
Function Call
"""

def plot_Top_fcns_Statistics():
    # with open(r"files\formatted_data\fcns.json", "r") as f:
    #     fcns = json.load(f)
    # total_fcns = []
    # for h in fcns:
    #     total_fcns.extend(fcns[h])
    # totalFcns_Counts = dict(sorted(Counter(total_fcns).items(), key=lambda item: item[1], reverse=True))
    with open(r"files\formatted_data\totalFcns_Counts.json", "r") as f:
        totalFcns_Counts = json.load(f)

    # Total fcns Statistics --> Top 100
    top50_fcns = list(totalFcns_Counts.keys())[:50]
    total_fcns_plot_data = {i:0 for i in top50_fcns}
    for op in top50_fcns:
        total_fcns_plot_data[op] = totalFcns_Counts[op]
    plot_dict_data(total_fcns_plot_data, r"files\resuls\Top 50 Used Frequently Function Calls Statistics.png", 
            "Statistics for Top 50 Frequently Used Function Calls ", "Function Calls", "The Number of Function Calls", 15, 8, 30, show_Barlabel=False)

def plot_fcnsPer_Architecures():
    # with open(r"files\formatted_data\fcns.json", "r") as f:
    #     fcns = json.load(f)
    # with open(r"files\formatted_data\architectures_hashcodes_dict.json", "r") as f:
    #     archi_hashes = json.load(f)
    # archi_fcns = {}
    # for archi in archi_hashes:
    #     if len(archi_hashes[archi]) > 0:
    #         fcns_list = []
    #         for h in fcns:
    #             if h in archi_hashes[archi]:
    #                 fcns_list.extend(fcns[h])
    #         fcns_list = dict(sorted(Counter(fcns_list).items(), key=lambda item: item[1], reverse=True))
    #         archi_fcns[archi] = fcns_list

    # with open(r"files\formatted_data\architectures_fcns.json", "w") as f:
    #     json.dump(archi_fcns, f)

    with open(r"files\formatted_data\architectures_fcns.json", "r") as f:
        archi_fcns = json.load(f)
    
    archi_types = list(archi_fcns.keys())
    archi_Top10_fcns = {i: [] for i in archi_types}

    for archi in archi_fcns:
        top10_names = list(archi_fcns[archi].keys())[:50] # 30
        top10_fcns = {}
        for fcn in top10_names:
            top10_fcns[fcn] = archi_fcns[archi][fcn]
        archi_Top10_fcns[archi] = top10_fcns
    print(archi_Top10_fcns)
    plot_data = {}
    count = 0
    for archi in archi_Top10_fcns:
        plot_data[count] = {
            "fcns_names": list(archi_Top10_fcns[archi].keys()),
            "fcns_counts": list(archi_Top10_fcns[archi].values()),
            "architecture": archi
        }
        count += 1

    # plot
    fig, axes = plt.subplots(2, int(len(archi_Top10_fcns)/2), figsize=(30, 15))
    fig.suptitle("Top 50 Frequently Used Function Calls for Each Architecture", x=0.5, y=0.998, fontsize=25)
    for i, ax in enumerate(axes.flatten()):
        if i in plot_data:
            ax.bar(plot_data[i]["fcns_names"], plot_data[i]["fcns_counts"])
            ax.set_title(plot_data[i]["architecture"])
            ax.tick_params('x', labelrotation=90, labelsize=8)
            ax.margins(x=0)
    plt.tight_layout()
    plt.savefig(r"files\resuls\Fcns Statistics on Each Architecture.png", dpi=300)
    # plt.show()


if __name__ == "__main__":
    # format_data()

    # architectures statistics
    # plot_ArchitectureStatistics()

    """
    opcodes statistics
    """
    # plot_Top_opcodes_Statistics()
    plot_opcodesPer_Architecures()

    """
    Fcns
    """
    # plot_Top_fcns_Statistics()
    plot_fcnsPer_Architecures()