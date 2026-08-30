"""
One-shot schema creation. Run locally once against your database, then set
AC_AUTO_MIGRATE=false so serverless cold starts skip the DDL.

    AC_DATABASE_URL="postgresql://..." python migrate.py
"""
import sys

import db

if __name__ == "__main__":
    print("backend: %s" % ("postgres" if db.IS_POSTGRES else "sqlite"))
    if not db.init_db(raise_on_error=True):
        print("FAILED - check AC_DATABASE_URL and that the database is reachable")
        sys.exit(1)
    print("schema ready")
    for table, count in sorted(db.storage_stats().items()):
        print("  %-14s %d rows" % (table, count))
