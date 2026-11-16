# cicd

API Flask de exemplo com uma esteira **CI/CD no GitHub Actions** que inclui análise **SAST**, **SCA** e **portões de qualidade (quality gates)** que bloqueiam o merge/deploy.

## Esteira

```mermaid
flowchart LR
    A[lint<br/>ruff] --> B[test<br/>pytest + cobertura]
    C[sast-bandit]
    D[sast-semgrep]
    E[sca-deps<br/>pip-audit + Trivy fs]
    B --> F[build-image<br/>Docker + Trivy image]
    C --> F
    D --> F
    E --> F
    F --> G{quality-gate}
    G -->|push na main| H[deploy<br/>GHCR]
```

| Job | Ferramenta | Tipo | Gate (bloqueia se...) |
|-----|-----------|------|------------------------|
| `lint` | ruff | Qualidade | houver erro de lint ou arquivo fora do padrão de formatação |
| `test` | pytest + pytest-cov | Qualidade | algum teste falhar ou cobertura < **80%** |
| `sast-bandit` | Bandit | SAST | houver achado de severidade **HIGH** (confiança ≥ medium) |
| `sast-semgrep` | Semgrep (`p/python`, `p/flask`, `p/secrets`) | SAST | houver achado de severidade **ERROR** |
| `sca-deps` | pip-audit + Trivy (fs) | SCA | dependência com vulnerabilidade conhecida (pip-audit) ou CVE **HIGH/CRITICAL** / segredo exposto (Trivy) |
| `build-image` | Docker + Trivy (image) | SCA | a imagem tiver CVE **HIGH/CRITICAL** com correção disponível |
| `quality-gate` | — | Agregador | qualquer job acima não terminar com `success` |
| `deploy` | GHCR | CD | roda só em `push` na `main` após o quality gate, no environment `production` |

Todos os relatórios SAST/SCA são enviados em formato SARIF para **Security → Code scanning** do repositório.
Nenhuma ferramenta exige token ou conta externa.

### Fluxo de branches

| Branch | Papel | O que roda |
|--------|-------|------------|
| `feature/*` | Desenvolvimento | nada (até abrir PR) |
| `test` | Integração / homologação | todos os gates em PR e push, **sem deploy** |
| `main` | Produção | todos os gates + **deploy** no GHCR |

Fluxo: `feature/*` → PR para `test` → PR de `test` para `main` → deploy.

### Proteção de branch

Em **Settings → Branches → Branch protection rules**, crie uma regra para `main` e outra para `test`:
1. Marque *Require a pull request before merging*.
2. Marque *Require status checks to pass before merging*.
3. Adicione o check **`Quality Gate`** como obrigatório.

Opcional: em **Settings → Environments → production**, adicione *Required reviewers* para aprovação manual antes do deploy.

## API

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/health` | Health check |
| GET | `/api/tasks` | Lista tarefas |
| POST | `/api/tasks` | Cria tarefa (`{"title": "...", "done": false}`) |
| GET | `/api/tasks/<id>` | Busca tarefa |
| PUT | `/api/tasks/<id>` | Atualiza tarefa |
| DELETE | `/api/tasks/<id>` | Remove tarefa |

## Rodando localmente os mesmos checks

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

ruff check . && ruff format --check .
pytest --cov=app --cov-fail-under=80
bandit -c pyproject.toml -r app --severity-level high --confidence-level medium
pip-audit -r requirements.txt --strict

# Semgrep e Trivy via Docker
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep \
  semgrep scan --config p/python --config p/flask --config p/secrets --severity ERROR --error
docker build -t cicd-demo .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy \
  image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 cicd-demo
```

Rodar a API:

```bash
docker run --rm -p 8000:8000 cicd-demo
curl localhost:8000/health
```

## Testando um gate reprovando

Crie uma branch e adicione algo inseguro em `app/routes.py`, por exemplo:

```python
import subprocess
subprocess.call(request.args["cmd"], shell=True)
```

Abra um PR: os jobs de SAST falham e o `Quality Gate` fica vermelho, bloqueando o merge.
