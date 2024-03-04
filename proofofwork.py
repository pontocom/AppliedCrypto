from cryptography.hazmat.primitives import hashes
import datetime
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

    print("|started\t\t|\t" + str(time_started))
    print("|index\t\t\t|\t" + str(index))
    print("|previous_hash\t|\t" + str(previous_hash))
    print("|timestamp\t\t|\t" + str(timestamp))
    print("|block data\t\t|\t" + b_data)
    print("|nonce\t\t\t|\t" + str(nonce-1))
    print("|new hash\t\t|\t" + c_hash)
    print("|ended\t\t\t|\t" + str(time_ended))
    print("|elapsed|\t\t|\t" + str(time_ended - time_started))

    return c_hash


if __name__ == '__main__':
    complexity = 5
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
