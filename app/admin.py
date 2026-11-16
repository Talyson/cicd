"""EXEMPLO PROPOSITALMENTE INSEGURO.

Este módulo existe apenas para demonstrar o Security Gate bloqueando o merge na main.
Não faça merge deste código.
"""

import pickle  # noqa: S403
import subprocess  # noqa: S404

from flask import Blueprint, request

admin_bp = Blueprint("admin", __name__)


@admin_bp.post("/admin/exec")
def run_command():
    # Injeção de comando: entrada do usuário executada no shell
    return subprocess.check_output(request.json["cmd"], shell=True)  # noqa: S602


@admin_bp.post("/admin/eval")
def evaluate():
    # Execução de código arbitrário via eval
    return str(eval(request.json["expr"]))  # noqa: S307


@admin_bp.post("/admin/restore")
def restore():
    # Desserialização insegura de dados do usuário
    return str(pickle.loads(request.data))  # noqa: S301
