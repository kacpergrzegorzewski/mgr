import sqlite3
import threading
from threading import Lock
import time


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper



class LDBSQLite:
    DELETE_OLD_FLOWS = True
    DELETE_OLD_FLOWS_INTERVAL = 5
    PRINT_LDB = True
    PRINT_LDB_INTERVAL = 10

    def __init__(self, filename):
        print("[INFO] Initializing LDB in " + filename)
        self.db_lock = Lock()
        self._init_db(filename)

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
        self._delete_old_flows()

    def get_outport(self, hash):
        self.db_lock.acquire(True)
        response = self.cursor.execute("SELECT outport FROM ldb WHERE hash=?", (hash,)).fetchone()
        self.db_lock.release()
        if response is None:
            return None
        else:
            return response[0]

    def get_all(self):
        self.db_lock.acquire(True)
        response = self.cursor.execute("SELECT * FROM ldb").fetchall()
        self.db_lock.release()
        return response

    @threaded
    def add_flow(self, hash, outport, endtime="4070908800"):  # 01.01.2099
        self.db_lock.acquire(True)
        self.cursor.execute("INSERT OR REPLACE INTO ldb(hash,outport,endtime) VALUES (?,?,?)",
                            (memoryview(hash), outport, endtime))
        self.db.commit()
        self.db_lock.release()

    @threaded
    def _delete_old_flows(self):
        while self.DELETE_OLD_FLOWS:
            current_time = str(int(time.time()))
            query = "DELETE FROM LDB WHERE endtime<" + current_time
            self.db_lock.acquire(True)
            self.cursor.execute(query)
            self.db.commit()
            self.db_lock.release()
            time.sleep(self.DELETE_OLD_FLOWS_INTERVAL)

    @threaded
    def _print_ldb(self):
        while self.PRINT_LDB:
            print("======== Current LDB state ========")
            rows = self.get_all()
            for row in rows:
                print(row)
            print("===================================")
            time.sleep(self.PRINT_LDB_INTERVAL)
