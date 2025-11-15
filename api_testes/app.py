
import os
import time
import datetime
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
import jwt

app = Flask(__name__)

# ----------------------------------------
# Configurações básicas
# ----------------------------------------

# Em produção: usar uma SECRET_KEY forte via variável de ambiente
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-trocar-em-producao")

# Configuração didática de tempo de expiração
ACCESS_TOKEN_MINUTES = 1    # curta duração para demonstrar expiração em aula
REFRESH_TOKEN_MINUTES = 30  # duração maior para refresh token

# Configuração do rate limit (didático)
RATE_LIMIT_REQUESTS = 10        # máx. de requisições
RATE_LIMIT_WINDOW_SEC = 60      # janela em segundos

# Armazena timestamps de requisições por IP (apenas em memória)
request_counters = defaultdict(list)


# ----------------------------------------
# "Banco de dados" em memória
# ----------------------------------------

USERS = [
    {
        "username": "alice",
        # Hash gerado com generate_password_hash("alice123")
        "password_hash": "scrypt:32768:8:1$N8lYvzcCR2cSeWZY$8819acf497d245d784fd4438a9d44067de083857a354c86de2389092d7e9f347d32d071208618b699b9007c2342298e07dfaf3569323d630829cf6a7e31f7556",
        "name": "Alice Exemplo"
    }
]

SONGS = [
    {"id": 1, "title": "Comfortably Numb", "artist": "Pink Floyd", "year": 1979},
    {"id": 2, "title": "Black", "artist": "Pearl Jam", "year": 1991},
    {"id": 3, "title": "Clocks", "artist": "Coldplay", "year": 2002},
    {"id": 4, "title": "Wish You Were Here", "artist": "Pink Floyd", "year": 1975},
]


# ----------------------------------------
# Helpers
# ----------------------------------------


def get_user_by_username(username: str):
    return next((u for u in USERS if u["username"] == username), None)


def generate_access_token(user):
    """Gera um JWT de acesso (curta duração)."""
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user["username"],
        "type": "access",
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "iat": now
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def generate_refresh_token(user):
    """Gera um JWT de refresh (duração maior)."""
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user["username"],
        "type": "refresh",
        "exp": now + datetime.timedelta(minutes=REFRESH_TOKEN_MINUTES),
        "iat": now
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def token_required(f):
    """Decorator para exigir ACCESS TOKEN no header Authorization: Bearer <token>."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = None

        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

        if not token:
            return jsonify({"message": "Token de acesso é necessário (Authorization: Bearer <token>)."}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            # Verifica se é token de acesso
            if data.get("type") != "access":
                return jsonify({"message": "Token informado não é um access token."}), 401

            current_user = get_user_by_username(data["sub"])
            if not current_user:
                return jsonify({"message": "Usuário do token não encontrado."}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Access token expirado."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token inválido."}), 401

        # Passa o usuário autenticado para a rota
        return f(current_user, *args, **kwargs)

    return decorated


def rate_limited():
    """
    Verifica se o IP atual ultrapassou o limite de requisições na janela.
    Retorna (bloqueado: bool, retry_after_segundos: int)
    """
    ip = request.remote_addr or "unknown"
    now = time.time()

    timestamps = request_counters[ip]

    # Remove timestamps fora da janela
    cutoff = now - RATE_LIMIT_WINDOW_SEC
    timestamps = [t for t in timestamps if t > cutoff]
    request_counters[ip] = timestamps

    if len(timestamps) >= RATE_LIMIT_REQUESTS:
        # Já passou do limite
        retry_after = int(timestamps[0] + RATE_LIMIT_WINDOW_SEC - now)
        return True, max(retry_after, 1)

    # Ainda não passou do limite, registra a requisição
    timestamps.append(now)
    request_counters[ip] = timestamps
    return False, 0


# ----------------------------------------
# Rotas
# ----------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Endpoint público – útil para monitoramento."""
    return jsonify({"status": "ok", "message": "API de músicas funcionando."})


@app.route("/auth/login", methods=["POST"])
def login():
    """
    Espera JSON:
    {
      "username": "alice",
      "password": "alice123"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "JSON obrigatório."}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Campos 'username' e 'password' são obrigatórios."}), 400

    user = get_user_by_username(username)
    # Resposta genérica para evitar enumeração de usuário
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "Credenciais inválidas."}), 401

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "access_expires_in_minutes": ACCESS_TOKEN_MINUTES,
        "refresh_expires_in_minutes": REFRESH_TOKEN_MINUTES,
        "user": {
            "username": user["username"],
            "name": user["name"]
        }
    })


@app.route("/auth/refresh", methods=["POST"])
def refresh():
    """
    Espera JSON:
    {
      "refresh_token": "<token>"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "JSON obrigatório."}), 400

    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"message": "Campo 'refresh_token' é obrigatório."}), 400

    try:
        payload = jwt.decode(refresh_token, app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("type") != "refresh":
            return jsonify({"message": "Token informado não é um refresh token."}), 401

        user = get_user_by_username(payload["sub"])
        if not user:
            return jsonify({"message": "Usuário do token não encontrado."}), 401

        # Gera novo access token
        new_access_token = generate_access_token(user)

        return jsonify({
            "access_token": new_access_token,
            "token_type": "Bearer",
            "access_expires_in_minutes": ACCESS_TOKEN_MINUTES
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Refresh token expirado. Faça login novamente."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Refresh token inválido."}), 401


@app.route("/songs", methods=["GET"])
@token_required
def list_songs(current_user):
    """
    Endpoint protegido: só retorna as músicas se o access token for válido.
    Também está protegido por rate limit simples (10 req/min por IP).
    """
    blocked, retry_after = rate_limited()
    if blocked:
        response = jsonify({
            "message": "Muitas requisições. Tente novamente mais tarde.",
            "hint": f"Limite de {RATE_LIMIT_REQUESTS} requisições a cada {RATE_LIMIT_WINDOW_SEC} segundos."
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    return jsonify({
        "user": {
            "username": current_user["username"],
            "name": current_user["name"]
        },
        "songs": SONGS
    })


if __name__ == "__main__":
    # Em produção: debug=False, host='0.0.0.0' e uso de HTTPS atrás de proxy reverso.
        app.run(host="0.0.0.0", port=5000, debug=True)
