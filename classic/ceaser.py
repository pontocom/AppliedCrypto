s= "carlos serrao"
nc=""

for c in s:
    if c == ' ':
        nc += c
        continue
    else:
        nc += chr(ord(c) ^ 13)

print(nc)

