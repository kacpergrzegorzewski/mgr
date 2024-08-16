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
    PRINT_STATISTICS = True
    PRINT_STATISTICS_INTERVAL = 10

    def __init__(self):
        # self.edge_lock = threading.Lock()
        self.sum_of_path_calculations_time = 0  # ms
        self.number_of_path_calculations = 0
        self.tdb = nx.DiGraph()
        self.print_current_state()
        self.remove_old_links()
        self.print_statistics()

    def update_node(self, node):
        # TODO remove nodes after NODE_TIMEOUT
        if node not in self.tdb.nodes:
            # self.edge_lock.acquire(True)
            self.tdb.add_node(node)
            # self.edge_lock.release()
            print("[INFO] Added node " + str(node) + " to TDB.")
        # else:
        #     print("[INFO] Node " + str(node) + " exists.")

    def get_link_source_iface(self, source, destination):
        try:
            return self.tdb.get_edge_data(source, destination)["src_iface"]
        except TypeError:
            print("[WARNING] Link src: " + str(source) + " dst: " + str(destination) + " not found!")

    def get_link_destination_iface(self, source, destination):
        try:
            return self.tdb.get_edge_data(source, destination)["dst_iface"]
        except TypeError:
            print("[WARNING] Link src: " + str(source) + " dst: " + str(destination) + " not found!")

    @threaded
    def update_link(self, start, end, src_iface, dst_iface, link_lifetime=10, weight=100):
        endtime = int(time.time() + link_lifetime)
        if start and end in self.tdb.nodes:
            if end == b'\x03^\xe5\xb5\xb3,\xfa\xa0\xd3e\x89\xd8Y+\xaf\xe5':  # Prefer Core02 in path
                weight = 10
            self.tdb.add_edge(start, end, src_iface=src_iface, dst_iface=dst_iface, endtime=endtime, weight=weight)
        else:
            print("[WARNING] Node does not exist. Link " + str(start) + " -> " + str(end) + " not created in TDB.")

    def get_all_nodes_name(self):
        # TODO
        return

    def get_path(self, source=None, destination=None):
        path = []
        time_before = time.time_ns()
        if source in self.tdb.nodes and destination in self.tdb.nodes:
            try:
                path = nx.shortest_path(self.tdb, source, destination, weight="weight").copy()
            except nx.exception.NetworkXNoPath:
                path = []
        time_after = time.time_ns()
        self.sum_of_path_calculations_time += (time_after - time_before) / 1_000_000  # ms
        self.number_of_path_calculations += 1
        return path


    def get_all_paths(self):
        return nx.shortest_path(self.tdb).copy()

    def get_neighbors(self, node):
        try:
            return self.tdb.adj[node].copy()
        except KeyError:
            return []

    @threaded
    def print_current_state(self):
        while self.TDB_PRINT:
            print("===============================================================")
            print("Current TDB state:")
            # self.edge_lock.acquire(True)
            for edge in self.tdb.edges:
                src_node = edge[0]
                dst_node = edge[1]
                src_iface = self.tdb.edges[src_node, dst_node]["src_iface"]
                dst_iface = self.tdb.edges[src_node, dst_node]["dst_iface"]
                print(str(src_node) + " (" + str(src_iface) + ")-> " + str(dst_node) + "(" + str(dst_iface) + ")")
            # self.edge_lock.release()
            print("===============================================================")
            time.sleep(self.TDB_PRINT_INTERVAL)

    @threaded
    def remove_old_links(self):
        while self.REMOVE_OLD_LINKS:
            current_time = time.time()
            to_remove = []
            # self.edge_lock.acquire(True)
            for edge in self.tdb.edges:
                if current_time > self.tdb.get_edge_data(*edge)["endtime"]:
                    to_remove.append(edge)
            for edge in to_remove:
                self.tdb.remove_edge(*edge)
            # self.edge_lock.release()
            time.sleep(self.REMOVE_OLD_LINKS_INTERVAL)

    @threaded
    def print_statistics(self):
        while self.PRINT_STATISTICS:
            print("============ statistics ============")
            print(time.ctime())
            if self.number_of_path_calculations != 0:
                print("Number of path calculations: " + str(self.number_of_path_calculations))
                print("Average path calculation time: " + str(self.sum_of_path_calculations_time/self.number_of_path_calculations) + "ms")
            print("====================================")
            time.sleep(self.PRINT_STATISTICS_INTERVAL)
