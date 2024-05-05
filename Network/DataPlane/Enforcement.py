from LDB import _LDB as LDB


class _Enforcement:
    def __init__(self, ldb, ldb_type="sqlite"):
        print("Initializing Enforcement")
        if ldb_type == "sqlite":
            self.ldb = LDB(ldb)

    def enforce(self, hash):
        print("enforcing " + str(hash))
