#!/bin/bash

# Caminho base (ajuste se necessário)
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Abre o servidor em um novo terminal
gnome-terminal -- bash -c "
cd \"$BASE_DIR\";
echo 'Iniciando servidor...';
python atividade2_server.py;
echo '';
read -p 'Pressione ENTER para fechar este terminal...'"

# Dá um pequeno delay para garantir que o servidor suba primeiro
sleep 1

# Abre o cliente em outro terminal
gnome-terminal -- bash -c "
cd \"$BASE_DIR\";
echo 'Iniciando cliente...';
python atividade2_client.py;
echo '';
read -p 'Pressione ENTER para fechar este terminal...'"
