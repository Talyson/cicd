"""Rotas HTTP da API de tarefas."""

from flask import Blueprint, current_app, jsonify, request

from app.models import TaskStore, ValidationError

bp = Blueprint("api", __name__)


def _store() -> TaskStore:
    return current_app.extensions["task_store"]


def _not_found():
    return jsonify(error="Tarefa não encontrada."), 404


@bp.errorhandler(ValidationError)
def handle_validation_error(exc: ValidationError):
    return jsonify(error=str(exc)), 400


@bp.get("/health")
def health():
    return jsonify(status="ok")


@bp.get("/api/tasks")
def list_tasks():
    return jsonify([task.to_dict() for task in _store().list()])


@bp.post("/api/tasks")
def create_task():
    task = _store().create(request.get_json(silent=True))
    return jsonify(task.to_dict()), 201


@bp.get("/api/tasks/<int:task_id>")
def get_task(task_id: int):
    task = _store().get(task_id)
    return jsonify(task.to_dict()) if task else _not_found()


@bp.put("/api/tasks/<int:task_id>")
def update_task(task_id: int):
    task = _store().update(task_id, request.get_json(silent=True))
    return jsonify(task.to_dict()) if task else _not_found()


@bp.delete("/api/tasks/<int:task_id>")
def delete_task(task_id: int):
    return ("", 204) if _store().delete(task_id) else _not_found()
