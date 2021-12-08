import networkx as nx
import matplotlib.pyplot as plt
import json, collections
import seaborn as sns
import textwrap
import pandas as pd
import matplotlib as mpl

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
    sns.set_style("whitegrid")
    ax = sns.barplot(x=x_data, y=y_data)
    ax.set(xlabel=xlabel, ylabel=ylabel)
    ax.set_title(title)
    plt.setp(ax.get_xticklabels(), rotation=rotation, ha="center", rotation_mode="anchor", fontsize=10)
    ax.tick_params(axis='x', which='major', pad=12)
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
                        textcoords='offset points', rotation=rotation)

    plt.tight_layout()
    plt.savefig(save_path)
    plt.show()

def plot_dict_data_DoubleBar(sourcedata, save_path, title, xlabel, ylabel, fig_w, fig_h, rotation, show_Barlabel=False, wrap_xticklabels=False):
    """[summary]

    Args:
        sourcedata ([type]): [description]
    """
    # plot_data = pd.DataFrame.from_dict(sourcedata, orient="index")
    plot_data = pd.DataFrame(sourcedata[1:], columns=sourcedata[0])
    plt.figure(figsize=(fig_w, fig_h))
    sns.set_style("darkgrid")
    g = sns.barplot(data=plot_data, x="IP Address", y="Value", hue="Type")
    g.set(xlabel=xlabel, ylabel=ylabel)
    g.set_title(title)
    g.tick_params(axis='x', rotation=rotation, labelsize=15)
    # print(plot_data)
    # # 将x轴坐标label折叠
    if wrap_xticklabels:
        f = lambda x: textwrap.fill(x.get_text(), 10)
        g.set_xticklabels(map(f, g.get_xticklabels()))

    # add label
    if show_Barlabel:
        for p in g.patches:
            g.annotate("%.0f" % p.get_height(), (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                        textcoords='offset points')
    plt.tight_layout()
    if len(save_path) == 0:
        plt.show()
    else:
        plt.savefig(save_path)
        plt.show()


def plot_pie_dict(dict_data, save_path):
    data = list(dict_data.values())
    labels = list(dict_data.keys())

    colors = sns.color_palette("pastel")
    plt.pie(data, labels=labels, colors=colors, autopct='%1.0f%%')
    plt.savefig(save_path)
    plt.show()

"""
vaddr=0x00000040 paddr=0x00000040 ord=011 fwd=NONE sz=11 bind=GLOBAL type=FUNC name=int_cmp
"""