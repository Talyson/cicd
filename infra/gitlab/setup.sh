#!/usr/bin/env bash
# Sobe o GitLab CE + Runner locais e configura o projeto da esteira CI/CD.
# Idempotente: pode ser executado novamente sem recriar o que já existe.
#
#   ./infra/gitlab/setup.sh
#
# Resultado:
#   - GitLab em http://localhost:8929 (usuário root, senha em infra/gitlab/.env)
#   - Projeto root/cicd com runner Docker registrado
#   - Branch main protegida (sem push direto) e "Pipelines must succeed" ativo
#   - Remote git "gitlab" (ssh://git@localhost:2222/root/cicd.git) com main e test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
ENV_FILE="$SCRIPT_DIR/.env"
GITLAB_URL="http://localhost:8929"
PROJECT_PATH="root/cicd"
PROJECT_ENC="root%2Fcicd"
SSH_PUBKEY="${SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

# ------------------------------------------------------------------ .env
if [[ ! -f "$ENV_FILE" ]]; then
  log "Gerando $ENV_FILE com senha aleatória para o root"
  umask 077
  printf 'GITLAB_ROOT_PASSWORD=%s\n' "$(openssl rand -base64 24 | tr -d '/+=')" > "$ENV_FILE"
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

set_env() {  # set_env CHAVE VALOR -> grava/atualiza no .env
  if grep -q "^$1=" "$ENV_FILE"; then
    sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
  fi
}

# ------------------------------------------------------------ containers
log "Subindo containers (a primeira inicialização do GitLab leva alguns minutos)"
docker compose --project-directory "$SCRIPT_DIR" --env-file "$ENV_FILE" up -d

printf 'Aguardando GitLab ficar healthy'
for _ in $(seq 1 120); do
  status="$(docker inspect -f '{{.State.Health.Status}}' gitlab 2>/dev/null || true)"
  [[ "$status" == "healthy" ]] && break
  printf '.'; sleep 10
done
echo
[[ "$status" == "healthy" ]] || { echo "GitLab não ficou healthy a tempo"; exit 1; }

# ------------------------------------------------------- token de API
api() {  # api MÉTODO caminho [args curl...]
  local method="$1" path="$2"; shift 2
  curl -fsS -X "$method" -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "$GITLAB_URL/api/v4/$path" "$@"
}

if [[ -z "${GITLAB_TOKEN:-}" ]] || ! api GET user >/dev/null 2>&1; then
  log "Criando Personal Access Token do root (via gitlab-rails, ~1 min)"
  GITLAB_TOKEN="$(docker exec gitlab gitlab-rails runner "
    user = User.find_by_username('root')
    user.personal_access_tokens.where(name: 'cicd-setup').each(&:revoke!)
    token = user.personal_access_tokens.create!(
      name: 'cicd-setup', scopes: %w[api write_repository], expires_at: 30.days.from_now)
    puts token.token
  " | tail -1)"
  set_env GITLAB_TOKEN "$GITLAB_TOKEN"
fi

# -------------------------------------------------- ajustes da instância
log "Ajustando instância (sem cadastro público, sem Auto DevOps)"
api PUT application/settings -d signup_enabled=false -d auto_devops_enabled=false >/dev/null

# --------------------------------------------------------------- projeto
if ! PROJECT_JSON="$(api GET "projects/$PROJECT_ENC" 2>/dev/null)"; then
  log "Criando projeto $PROJECT_PATH"
  PROJECT_JSON="$(api POST projects -d name=cicd -d path=cicd -d visibility=private \
    -d initialize_with_readme=false)"
fi
PROJECT_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$PROJECT_JSON")"
echo "Projeto id: $PROJECT_ID"

# ---------------------------------------------------------------- runner
if ! docker exec gitlab-runner gitlab-runner list 2>&1 | grep -q 'Executor=docker'; then
  log "Registrando runner Docker"
  RUNNER_TOKEN="$(api POST user/runners -d runner_type=instance_type \
    -d description=local-docker -d run_untagged=true |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  docker exec gitlab-runner gitlab-runner register --non-interactive \
    --url http://gitlab:8929 \
    --clone-url http://gitlab:8929 \
    --token "$RUNNER_TOKEN" \
    --description local-docker \
    --executor docker \
    --docker-image python:3.12-slim \
    --docker-network-mode gitlab-net \
    --docker-volumes /var/run/docker.sock:/var/run/docker.sock \
    --docker-pull-policy if-not-present
  docker exec gitlab-runner sed -i 's/^concurrent = .*/concurrent = 4/' /etc/gitlab-runner/config.toml
fi

# ------------------------------------------------------ chave SSH + push
if [[ -f "$SSH_PUBKEY" ]]; then
  KEY="$(cut -d' ' -f1,2 "$SSH_PUBKEY")"
  if ! api GET user/keys | grep -qF "${KEY#* }"; then
    log "Cadastrando chave SSH $SSH_PUBKEY no usuário root"
    api POST user/keys --data-urlencode "title=$(hostname)" --data-urlencode "key=$KEY" >/dev/null
  fi
fi

cd "$REPO_DIR"
REMOTE_URL="ssh://git@localhost:2222/$PROJECT_PATH.git"
if git remote get-url gitlab >/dev/null 2>&1; then
  git remote set-url gitlab "$REMOTE_URL"
else
  git remote add gitlab "$REMOTE_URL"
fi

if ! api GET "projects/$PROJECT_ID/repository/branches/main" >/dev/null 2>&1; then
  log "Enviando branch atual ($(git branch --show-current)) como main e test"
  GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=accept-new" git push gitlab HEAD:main HEAD:test
fi

# ------------------------------------------- bloqueio de merge na main
log "Configurando bloqueio de merge (pipeline obrigatório + main protegida)"
api PUT "projects/$PROJECT_ID" \
  -d only_allow_merge_if_pipeline_succeeds=true \
  -d allow_merge_on_skipped_pipeline=false \
  -d remove_source_branch_after_merge=false >/dev/null

protect() {  # protect BRANCH PUSH_LEVEL MERGE_LEVEL  (0 = ninguém, 40 = maintainers)
  api DELETE "projects/$PROJECT_ID/protected_branches/$1" >/dev/null 2>&1 || true
  api POST "projects/$PROJECT_ID/protected_branches" -d "name=$1" \
    -d "push_access_level=$2" -d "merge_access_level=$3" -d allow_force_push=false >/dev/null
}
protect main 0 40   # main: ninguém faz push direto; só merge via MR (com pipeline verde)
protect test 40 40  # test: maintainers podem fazer push

log "Pronto"
cat <<EOF
GitLab:    $GITLAB_URL  (usuário: root, senha: GITLAB_ROOT_PASSWORD em $ENV_FILE)
Projeto:   $GITLAB_URL/$PROJECT_PATH
Pipelines: $GITLAB_URL/$PROJECT_PATH/-/pipelines
Registry:  localhost:5050/$PROJECT_PATH
Remote:    git remote "gitlab" -> $REMOTE_URL
EOF
