import sqlite3


class LDBSQLite:
    def __init__(self, filename):
        print("Initializing LDB in " + filename)
        self._init_db(filename)

    def _init_db(self, filename):
        self.db = sqlite3.connect(filename, check_same_thread=False)
        self.cursor = self.db.cursor()
        result = self.cursor.execute("PRAGMA table_info(ldb)")
        if result.fetchone() is None:
            self.cursor.execute("CREATE TABLE ldb(hash BLOB PRIMARY KEY ON CONFLICT REPLACE, outport, endtime)")

    def get_outport(self, hash):
        response = self.cursor.execute("SELECT outport FROM ldb WHERE hash=?", (hash,)).fetchone()
        if response is None:
            return None
        else:
            return response[0]

    def get_all(self):
        return self.cursor.execute("SELECT * FROM ldb").fetchall()

    def add_flow(self, hash, outport, endtime="2099-01-01 12:00:00"):
        self.cursor.execute("INSERT OR REPLACE INTO ldb(hash,outport,endtime) VALUES (?,?,?)", (memoryview(hash), outport, endtime))
        self.db.commit()

