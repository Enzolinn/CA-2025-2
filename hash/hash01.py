import hashlib

mensagem = input("Digite uma mensagem: ")
hash_obj = hashlib.md5(mensagem.encode())
print("SHA-256:", hash_obj.hexdigest())
