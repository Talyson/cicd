"""Armazenamento em memória de tarefas, com validação de entrada."""

from dataclasses import asdict, dataclass
from threading import Lock

MAX_TITLE_LENGTH = 200


class ValidationError(ValueError):
    """Erro de validação dos dados de entrada."""


@dataclass
class Task:
    id: int
    title: str
    done: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def validate_payload(data: object, partial: bool = False) -> dict:
    if not isinstance(data, dict):
        raise ValidationError("O corpo da requisição deve ser um objeto JSON.")

    cleaned: dict = {}
    if "title" in data or not partial:
        title = data.get("title")
        if not isinstance(title, str) or not title.strip():
            raise ValidationError("'title' é obrigatório e deve ser uma string não vazia.")
        if len(title) > MAX_TITLE_LENGTH:
            raise ValidationError(f"'title' deve ter no máximo {MAX_TITLE_LENGTH} caracteres.")
        cleaned["title"] = title.strip()

    if "done" in data:
        if not isinstance(data["done"], bool):
            raise ValidationError("'done' deve ser booleano.")
        cleaned["done"] = data["done"]

    return cleaned


class TaskStore:
    def __init__(self) -> None:
        self._tasks: dict[int, Task] = {}
        self._next_id = 1
        self._lock = Lock()

    def list(self) -> list[Task]:
        return list(self._tasks.values())

    def get(self, task_id: int) -> Task | None:
        return self._tasks.get(task_id)

    def create(self, data: object) -> Task:
        cleaned = validate_payload(data)
        with self._lock:
            task = Task(id=self._next_id, **cleaned)
            self._tasks[task.id] = task
            self._next_id += 1
        return task

    def update(self, task_id: int, data: object) -> Task | None:
        cleaned = validate_payload(data, partial=True)
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            for key, value in cleaned.items():
                setattr(task, key, value)
        return task

    def delete(self, task_id: int) -> bool:
        with self._lock:
            return self._tasks.pop(task_id, None) is not None
