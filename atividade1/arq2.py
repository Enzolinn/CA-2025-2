from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hmac, hashlib


chave_aes = get_random_bytes(16)  
chave_hmac = b"chave_hmac_supersecreta"


mensagem = b"Mensagem confidencial: liberar acesso"

cipher = AES.new(chave_aes, AES.MODE_CBC)
iv = cipher.iv
ciphertext = cipher.encrypt(pad(mensagem, AES.block_size))  
print("Mensagem criptografada:", ciphertext.hex())


mac = hmac.new(chave_hmac, iv + ciphertext, hashlib.sha256).hexdigest()
print("HMAC do ciphertext:", mac)


mac_recebido = mac 
verifica = hmac.compare_digest(mac_recebido, hmac.new(chave_hmac, iv + ciphertext, hashlib.sha256).hexdigest())
print("Mensagem íntegra?", verifica)

ciphertext_alterado = ciphertext[:-1] + b'\x00' 
mac_verificacao = hmac.new(chave_hmac, iv + ciphertext_alterado, hashlib.sha256).hexdigest()
print("\nHMAC após adulteração:", mac_verificacao)
print("Mensagem íntegra após adulteração?", hmac.compare_digest(mac, mac_verificacao))


if verifica:
    decipher = AES.new(chave_aes, AES.MODE_CBC, iv)
    mensagem_decifrada = unpad(decipher.decrypt(ciphertext), AES.block_size)
    print("\nMensagem decifrada:", mensagem_decifrada.decode())
else:
    print("\nMensagem foi alterada! Não é seguro decifrar.")
