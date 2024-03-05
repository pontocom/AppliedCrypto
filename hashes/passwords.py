import sqlite3, os, base64
import prettytable
from sqlite3 import Error
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('acounts.db')
        return conn
    except Error as e:
        print(e)


def create_table(conn, sql):
    try:
        c = conn.cursor()
        c.execute(sql)
    except Error as e:
        print(e)


def create_user(conn, user):
    sql = ''' INSERT INTO users(username, salt, password) VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    return True


def get_salt(conn, user):
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username=?', [user])
    row = cur.fetchone()
    if row is None:
        return False
    else:
        return row[1]


def check_account(conn, user, password):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?", (user, password))
    if cur.fetchone() is None:
        return False
    else:
        return True


def list_all_accounts(conn):
    table = prettytable.PrettyTable(["Username", "Salt", "Password"])
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    rows = cur.fetchall()
    for row in rows:
        table.add_row(row)
        # print("["+row[0]+"] ["+row[1]+"]")
    print(table)


if __name__ == '__main__':
    c = create_connection()
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS users (
                                            username text PRIMARY KEY,
                                            salt text NOT NULL,
                                            password text NOT NULL
                                        ); """
    create_table(c, sql_create_projects_table)

    while True:
        print("Menu")
        print("[1] Login")
        print("[2] Criar Utilizador")
        print("[3] Listar Utilizador")
        print("[0] Sair")
        option = input("->")

        if option == '1':
            username = input("Username: ")
            password = input("Password: ")
            salt = get_salt(c, username)
            if not salt:
                print("Wrong username!!!")
                continue
            passphrase = password.encode('utf8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA3_256(),
                length=32,
                salt=bytes.fromhex(salt),
                iterations=100000
            )
            key = base64.urlsafe_b64encode(kdf.derive(passphrase))
            if check_account(c, username, key.hex()):
                print("Username and Password are CORRECT!")
            else:
                print("WRONG Credentials!!!")
        elif option == '2':
            username = input("Username: ")
            password = input("Password: ")
            salt = os.urandom(16)
            passphrase = password.encode('utf8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA3_256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = base64.urlsafe_b64encode(kdf.derive(passphrase))
            user = (username, salt.hex(), key.hex())
            create_user(c, user)
        elif option == '3':
            list_all_accounts(c)
        elif option == '0':
            break
        else:
            continue
