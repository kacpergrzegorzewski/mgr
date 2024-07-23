import sqlite3
import threading
import time


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class LDBSQLite:
    DELETE_OLD_FLOWS = True
    DELETE_OLD_FLOWS_INTERVAL = 5

    def __init__(self, filename):
        print("[INFO] Initializing LDB in " + filename)
        self._init_db(filename)

    def _init_db(self, filename):
        self.db = sqlite3.connect(filename, check_same_thread=False)
        self.cursor = self.db.cursor()
        result = self.cursor.execute("PRAGMA table_info(ldb)")
        if result.fetchone() is None:
            self.cursor.execute("CREATE TABLE ldb(hash BLOB PRIMARY KEY ON CONFLICT REPLACE, outport, endtime)")
        self._delete_old_flows()

    def get_outport(self, hash):
        response = self.cursor.execute("SELECT outport FROM ldb WHERE hash=?", (hash,)).fetchone()
        if response is None:
            return None
        else:
            return response[0]

    def get_all(self):
        return self.cursor.execute("SELECT * FROM ldb").fetchall()

    def add_flow(self, hash, outport, endtime="4070908800"):
        self.cursor.execute("INSERT OR REPLACE INTO ldb(hash,outport,endtime) VALUES (?,?,?)",
                            (memoryview(hash), outport, endtime))
        self.db.commit()

    @threaded
    def _delete_old_flows(self):
        while self.DELETE_OLD_FLOWS:
            self.cursor.execute("DELETE FROM LDB WHERE endtime<?", (str(int(time.time()))))
            time.sleep(self.DELETE_OLD_FLOWS_INTERVAL)
