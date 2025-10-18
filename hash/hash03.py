import bcrypt

def hash_bcrypt(password: str, rounds: int = 12):
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()  # armazene a string

def verify_bcrypt(stored: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored.encode())

# uso
h = hash_bcrypt("minhaSenha", rounds=12)
print(h)
print("ok:", verify_bcrypt(h, "minhaSenha"))
