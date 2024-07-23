import sqlite3
import threading
from threading import Lock
import time


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


lock = Lock()


class LDBSQLite:
    DELETE_OLD_FLOWS = True
    DELETE_OLD_FLOWS_INTERVAL = 5

    def __init__(self, filename):
        print("[INFO] Initializing LDB in " + filename)
        self._init_db(filename)

    def _init_db(self, filename):
        self.db = sqlite3.connect(filename, check_same_thread=False)
        self.cursor = self.db.cursor()
        lock.acquire(True)
        result = self.cursor.execute("PRAGMA table_info(ldb)")
        lock.release()
        if result.fetchone() is None:
            lock.acquire(True)
            self.cursor.execute("CREATE TABLE ldb(hash BLOB PRIMARY KEY ON CONFLICT REPLACE, outport, endtime)")
            lock.release()
        self._delete_old_flows()

    def get_outport(self, hash):
        lock.acquire(True)
        response = self.cursor.execute("SELECT outport FROM ldb WHERE hash=?", (hash,)).fetchone()
        lock.release()
        if response is None:
            return None
        else:
            return response[0]

    def get_all(self):
        lock.acquire(True)
        response = self.cursor.execute("SELECT * FROM ldb").fetchall()
        lock.release()
        return response

    def add_flow(self, hash, outport, endtime="4070908800"):
        lock.acquire(True)
        self.cursor.execute("INSERT OR REPLACE INTO ldb(hash,outport,endtime) VALUES (?,?,?)",
                            (memoryview(hash), outport, endtime))
        self.db.commit()
        lock.release()

    @threaded
    def _delete_old_flows(self):
        while self.DELETE_OLD_FLOWS:
            lock.acquire(True)
            self.cursor.execute("DELETE FROM LDB WHERE endtime<?", (str(int(time.time()))))
            lock.release()
            time.sleep(self.DELETE_OLD_FLOWS_INTERVAL)
