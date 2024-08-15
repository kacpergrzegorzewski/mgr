import sqlite3
import threading
from threading import Lock
import time


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class FixSizedDict(dict):
    def __init__(self, *args, maxlen=0, **kwargs):
        self._maxlen = maxlen
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        if self._maxlen > 0:
            if len(self) > self._maxlen:
                self.pop(next(iter(self)))


class LDBCache:
    def __init__(self, maxlen=0):
        self.queue = FixSizedDict(maxlen=maxlen)

    def add(self, flow, outport):
        self.queue[flow] = outport

    def remove(self, flow):
        self.queue.pop(flow)

    def remove_many(self, flows):
        for flow in flows:
            self.remove(flow)

    def is_hit(self, flow):
        return flow in self.queue

    def get_outport(self, flow):
        return self.queue[flow]


class LDBSQLite:
    DELETE_OLD_FLOWS = True
    DELETE_OLD_FLOWS_INTERVAL = 0.5
    PRINT_LDB = True
    PRINT_LDB_INTERVAL = 10

    def __init__(self, filename, cache_size=0):
        print("[INFO] Initializing LDB in " + filename)
        self.number_of_lookups = 0
        self.sum_of_lookup_time = 0
        self.number_of_writes = 0
        self.sum_of_write_time = 0
        self.db_lock = Lock()
        self.cache = LDBCache(maxlen=cache_size)
        self._init_db(filename)
        self._delete_old_flows()
        self._print_ldb()

    def _init_db(self, filename):
        self.db = sqlite3.connect(filename, check_same_thread=False)
        self.cursor = self.db.cursor()
        self.db_lock.acquire(True)
        result = self.cursor.execute("PRAGMA table_info(ldb)")
        self.db_lock.release()
        if result.fetchone() is None:
            self.db_lock.acquire(True)
            self.cursor.execute("CREATE TABLE ldb(hash BLOB PRIMARY KEY ON CONFLICT REPLACE, outport, endtime)")
            self.db_lock.release()

    def get_outport(self, hash):
        if self.cache.is_hit(hash):
            return self.cache.get_outport(hash)
        self.number_of_lookups += 1
        time_before = time.time_ns()
        self.db_lock.acquire(True)
        response = self.cursor.execute("SELECT outport FROM ldb WHERE hash=?", (hash,)).fetchone()
        self.db_lock.release()
        time_after = time.time_ns()
        self.sum_of_lookup_time += (time_after - time_before) / 1_000_000  # time in ms
        if response is None:
            return None
        else:
            outport = response[0]
            self.cache.add(hash, outport)
            return outport

    def get_all(self):
        self.db_lock.acquire(True)
        response = self.cursor.execute("SELECT * FROM ldb").fetchall()
        self.db_lock.release()
        return response

    @threaded
    def add_flow(self, hash, outport, endtime="4070908800"):  # 01.01.2099
        self.cache.add(hash, outport)
        time_before = time.time_ns()
        self.db_lock.acquire(True)
        self.cursor.execute("INSERT OR REPLACE INTO ldb(hash,outport,endtime) VALUES (?,?,?)",
                            (memoryview(hash), outport, endtime))
        self.db.commit()
        self.db_lock.release()
        time_after = time.time_ns()
        self.sum_of_write_time += (time_after - time_before) / 1_000_000  # ms
        self.number_of_writes += 1

    @threaded
    def _delete_old_flows(self):
        while self.DELETE_OLD_FLOWS:
            current_time = str(int(time.time()))
            query_delete = "DELETE FROM LDB WHERE endtime<" + current_time
            query_select = "SELECT hash FROM LDB WHERE endtime<" + current_time
            self.db_lock.acquire(True)
            self.cursor.execute(query_delete)
            to_remove = self.cursor.execute(query_select)
            self.db.commit()
            self.db_lock.release()
            self.cache.remove_many(to_remove)
            time.sleep(self.DELETE_OLD_FLOWS_INTERVAL)

    @threaded
    def _print_ldb(self):
        while self.PRINT_LDB:
            print("========================= Current LDB state =========================")
            print(time.ctime())
            if self.number_of_lookups != 0:
                print("Average read time: " + str(self.sum_of_lookup_time / self.number_of_lookups) + "ms")
            if self.number_of_writes != 0:
                print("Average write time: " + str(self.sum_of_write_time / self.number_of_writes) + "ms")
            print("flow,outport,endtime")
            rows = self.get_all()
            for row in rows:
                print(row)
            print(self.cache.queue)
            print("=====================================================================")
            time.sleep(self.PRINT_LDB_INTERVAL)
