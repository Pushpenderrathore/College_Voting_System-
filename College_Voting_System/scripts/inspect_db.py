import sqlite3
import json

DB = 'database.db'
conn = sqlite3.connect(DB)
cur = conn.cursor()
print('Tables and schema:')
for row in cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"):
    print('\nTABLE:', row[0])
    print(row[1])

print('\nSample rows from users:')
try:
    for r in cur.execute('SELECT * FROM users LIMIT 10'):
        print(r)
except Exception as e:
    print('Error querying users:', e)

print('\nPRAGMA table_info(users):')
for r in cur.execute("PRAGMA table_info('users')"):
    print(r)

conn.close()