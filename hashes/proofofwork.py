from cryptography.hazmat.primitives import hashes
import datetime
import prettytable
from halo import Halo


def check(hash, complexity):
    pw = hash[0:complexity]
    for c in pw:
        if c != '0':
            return False
    return True


def calculate_hash(index, previous_hash, timestamp, b_data, complexity):
    nonce = 0
    c_hash = '----------------------------------------------------------------'
    time_started = datetime.datetime.now()
    with Halo(text='Computing', spinner='dots'):
        while not check(c_hash, complexity):
            block = str(index)+':'+str(previous_hash)+':'+str(timestamp)+':' + b_data + ":" + str(nonce)
            sha256 = hashes.Hash(hashes.SHA256())
            sha256.update(block.encode('ascii'))
            sha256_hash = sha256.finalize()
            c_hash = sha256_hash.hex()
            nonce = nonce + 1
    time_ended = datetime.datetime.now()

    table = prettytable.PrettyTable(["Data", "Value"])
    table.align = "l"
    table.add_row(["Started", str(time_started)])
    table.add_row(["Block Index", str(index)])
    table.add_row(["Previous Hash", str(previous_hash)])
    table.add_row(["Timestamp", str(timestamp)])
    table.add_row(["Block Data", b_data])
    table.add_row(["Nonce", str(nonce-1)])
    table.add_row(["New Hash", c_hash])
    table.add_row(["Ended", str(time_ended)])
    table.add_row(["Elapsed Time", str(time_ended - time_started)])
    print(table)

    return c_hash


if __name__ == '__main__':
    complexity = 6
    index = 0
    genesys_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    data = ''

    while True:
        data = input("Data for the block ["+ str(index) +"] [EXIT to terminate]: ")
        if data == 'EXIT' or data == 'exit':
            print("Bye bye!")
            exit()
        if index == 0:
            previous_hash = genesys_block_hash
        timestamp = datetime.datetime.now()
        new_block_hash = calculate_hash(index, previous_hash, timestamp, data, complexity)
        previous_hash = new_block_hash
        index = index + 1
