from .LDB import LDBSQLite as LDBSQLite


class _Enforcement:
    def __init__(self, ldb: LDBSQLite):
        """
        Init function
        :param ldb: LDB name (depends on ldb_type)
        :param ldb_type: (default sqlite) type of LDB
        """
        print("Initializing Enforcement")

        self.ldb = ldb
    # TODO other LDB types e.g. mysql

    def enforce(self, hash):
        outport = self.ldb.get_outport(hash)
        print("[INFO] enforcing " + str(hash))
        return outport
