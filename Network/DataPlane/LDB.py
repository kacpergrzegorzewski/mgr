import sqlite3


class LDBSQLite:
    def __init__(self, filename):
        print("Initializing LDB in " + filename)
        self._init_db(filename)

    def _init_db(self, filename):
        self.db = sqlite3.connect(filename)
        cursor = self.db.cursor()
        result = cursor.execute("PRAGMA table_info(ldb)")
        if result is None:
            cursor.execute("CREATE TABLE ldb(hash, outport, endtime)")

    def get_outport(self, hash):
        cursor = self.db.cursor()
        return cursor.execute("SELECT outport FROM ldb WHERE hash=?", (hash,))

    def put(self, hash, outport, endtime="2099-01-01 12:00:00"):
        cursor = self.db.cursor()
        cursor.execute("INSERT INTO ldb(hash,outport,endtime) VALUES(?,?,?)", (hash, outport, endtime))


if __name__ == '__main__':
    filename = "../../DB/LDB-test01.db"
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # cursor.execute("CREATE TABLE ldb(hash, outport, endtime)")

    hash = "abc"
    outport = "2"
    endtime = "15:24"
    # cursor.execute("INSERT INTO ldb(hash,outport,endtime) VALUES(?,?,?)", (hash, outport, endtime))
    # db.commit()
    response = cursor.execute("SELECT outport FROM LDB WHERE hash=?", (hash,))
    print(response.fetchone())
