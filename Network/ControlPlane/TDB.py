import threading
import time
import networkx as nx

from ..Base.Env import *


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()
    return wrapper


class _Node:
    def __init__(self, name, endtime):
        self.name = name
        self.endtime = endtime


class TDB:
    TDB_PRINT = True
    TDB_PRINT_INTERVAL = 10
    REMOVE_OLD_LINKS = True
    REMOVE_OLD_LINKS_INTERVAL = 1

    def __init__(self):
        self.tdb = nx.DiGraph()
        self.print_current_state()
        self.remove_old_links()

    def update_node(self, node):
        # TODO remove nodes after NODE_TIMEOUT
        if node not in self.tdb.nodes:
            self.tdb.add_node(node)
            print("[INFO] Added node " + str(node) + " to TDB.")
        # else:
        #     print("[INFO] Node " + str(node) + " exists.")

    def get_link_source_iface(self, source, destination):
        return self.tdb.get_edge_data(source, destination)["src_iface"]

    def get_link_destination_iface(self, source, destination):
        return self.tdb.get_edge_data(source, destination)["dst_iface"]

    def update_link(self, start, end, src_iface, dst_iface, link_lifetime=10):
        endtime = int(time.time() + link_lifetime)
        if start and end in self.tdb.nodes:
            self.tdb.add_edge(start, end, src_iface=src_iface, dst_iface=dst_iface, endtime=endtime)
        else:
            print("[WARNING] Node does not exist. Link " + str(start) + " -> " + str(end) + " not created in TDB.")

    def get_all_nodes_name(self):
        # TODO
        return

    def get_path(self, source=None, destination=None):
        if source in self.tdb.nodes and destination in self.tdb.nodes:
            try:
                return nx.shortest_path(self.tdb, source, destination)
            except nx.exception.NetworkXNoPath:
                return []
        return []

    def get_all_paths(self):
        return nx.shortest_path(self.tdb)

    def get_neighbors(self, node):
        try:
            return self.tdb.adj[node]
        except KeyError:
            return []

    @threaded
    def print_current_state(self):
        while self.TDB_PRINT:
            print("===============================================================")
            print("Current TDB state:")
            edges = self.tdb.edges
            for edge in edges:
                src_node = edge[0]
                dst_node = edge[1]
                src_iface = self.tdb.edges[src_node, dst_node]["src_iface"]
                dst_iface = self.tdb.edges[src_node, dst_node]["dst_iface"]
                print(str(src_node) + " (" + str(src_iface) + ")-> " + str(dst_node) + "(" + str(dst_iface) + ")")
            print("===============================================================")
            time.sleep(self.TDB_PRINT_INTERVAL)

    @threaded
    def remove_old_links(self):
        while self.REMOVE_OLD_LINKS:
            current_time = time.time()
            edges = self.tdb.edges
            for edge in edges:
                if current_time > self.tdb.get_edge_data(*edge)["endtime"]:
                    self.tdb.remove_edge(*edge)
            time.sleep(self.REMOVE_OLD_LINKS_INTERVAL)
