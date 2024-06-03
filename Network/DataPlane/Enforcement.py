from LDB import _LDBSQLite as LDB


class _Enforcement:
    def __init__(self, ldb, ldb_type="sqlite"):
        """
        Init function
        :param ldb: LDB name (depends on ldb_type)
        :param ldb_type: (default sqlite) type of LDB
        """
        print("Initializing Enforcement")
        if ldb_type == "sqlite":
            self.ldb = LDB(ldb)
    # TODO other LDB types e.g. mysql

    def enforce(self, hash):
        print("enforcing " + str(hash))
