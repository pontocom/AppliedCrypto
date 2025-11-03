'''
This is an example of how to use the Ceaser cipher!
'''

s= 'carlos serrao'
nc=''

for c in s:
    if c == ' ':
        nc += c
        continue
    else:
        nc += chr(ord(c) ^ 3)

print(f'Cleartext = {s}')
print(f'Encrypted = {nc}')

