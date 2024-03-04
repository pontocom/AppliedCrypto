from cryptography.hazmat.primitives import hashes

message = "this is my message"

md5 = hashes.Hash(hashes.SHA3_512())
md5.update(message.encode('ascii'))
md5_hash = md5.finalize()

print(md5_hash.hex())