import hmac
import hashlib

mensagem = b"Acesso liberado para o servidor"
chave = b"chave_supersecreta"

hmac_original = hmac.new(chave, mensagem, hashlib.sha256).hexdigest()
print("HMAC original:", hmac_original)

verificacao = hmac.compare_digest(hmac_original, hmac.new(chave, mensagem, hashlib.sha256).hexdigest())
print("Mensagem íntegra?", verificacao)

mensagem_alterada = b"Acesso liberado para o servidOr"
hmac_alterado = hmac.new(chave, mensagem_alterada, hashlib.sha256).hexdigest()
verificacao2 = hmac.compare_digest(hmac_original, hmac_alterado)
print("\nMensagem alterada:", mensagem_alterada)
print("HMAC alterado:", hmac_alterado)
print("Mensagem íntegra após alteração?", verificacao2)
