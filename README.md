# SMB Singlefile CLI

Servidor SMB2/SMB3 em C++ (arquivo único: `smb.cpp`) com build reprodutível via Zig e matriz de cross-compilação para distribuição.

## Objetivo

Este projeto prioriza:

- Binário único e sem dependências externas em runtime
- Build nativo rápido para desenvolvimento
- Build cross-plataforma para release
- Pipeline de CI/CD com empacotamento por target e publicação em GitHub Release

## Recursos

- Comandos CLI:
  - `serve`
  - `smoke-client`
  - `self-test`
  - `version`
  - `help`
- Operações SMB implementadas:
  - `NEGOTIATE`, `SESSION_SETUP`, `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`
  - `CREATE`, `WRITE`, `READ`, `CLOSE`, `FLUSH`, `LOCK`, `IOCTL`, `CANCEL`, `ECHO`
  - `QUERY_INFO`, `QUERY_DIRECTORY`, `CHANGE_NOTIFY`, `SET_INFO`, `OPLOCK_BREAK`
- Autenticação NTLM (com opção de bloquear legados)
- Assinatura SMB2 (`SMB signing`) opcional por sessão autenticada
- Hardening de share (`read-only`, limite de handles, limite de tamanho de arquivo)
- Bloqueio de traversal/symlink-escape e dotfiles por padrão
- Perfil de produção com defaults mais seguros (`--prod-profile`)

## Requisitos

- Zig `0.15.2`
- Cosmocc `4.0.2` (opcional, para target Cosmo `.com`)
- Linux/macOS/Windows para build local

Versão recomendada:

```bash
zig version
# esperado: 0.15.2
```

## Build

Build nativo (rápido, para desenvolvimento local):

```bash
zig build native -Doptimize=ReleaseFast
```

O binário nativo fica em:

- `release/bin/smb_cli`

Build completo da matriz de targets:

```bash
zig build matrix -Doptimize=ReleaseFast
```

Build do alvo Cosmopolitan (`.com`):

```bash
zig build cosmo -Doptimize=ReleaseFast
```

Se o wrapper C++ disponível no ambiente não for `cosmoc++`, sobrescreva o comando:

```bash
zig build cosmo -Doptimize=ReleaseFast -Dcosmo-cxx=cosmocc
```

Observação: o build tenta autodetectar `cosmoc++`/`cosmocc++`/`cosmocc` no `PATH` e converte automaticamente `cosmocc` para `cosmoc++`.

Build completo (matriz + cosmo):

```bash
zig build matrix cosmo -Doptimize=ReleaseFast
```

## Matriz de cross-compilação

Artefatos gerados em `release/bin`:

- `smb_cli_linux_x86_64` (`x86_64-linux-musl`)
- `smb_cli_linux_x86` (`x86-linux-musl`)
- `smb_cli_linux_armv6` (`arm-linux-musleabihf`, CPU `arm1176jzf_s`)
- `smb_cli_linux_armv7` (`arm-linux-musleabihf`, CPU `cortex_a7`)
- `smb_cli_linux_arm64` (`aarch64-linux-musl`)
- `smb_cli_linux_riscv64` (`riscv64-linux-musl`)
- `smb_cli_linux_mips` (`mips-linux-musleabi`)
- `smb_cli_linux_mipsel` (`mipsel-linux-musleabi`)
- `smb_cli_linux_mips_hf` (`mips-linux-musleabihf`)
- `smb_cli_linux_mipsel_hf` (`mipsel-linux-musleabihf`)
- `smb_cli_linux_mips64` (`mips64-linux-muslabi64`)
- `smb_cli_linux_mips64el` (`mips64el-linux-muslabi64`)
- `smb_cli_linux_mips64n32` (`mips64-linux-muslabin32`)
- `smb_cli_linux_mips64eln32` (`mips64el-linux-muslabin32`)
- `smb_cli_macos_x86_64` (`x86_64-macos`)
- `smb_cli_macos_arm64` (`aarch64-macos`)
- `smb_cli_windows_x86.exe` (`x86-windows-gnu`)
- `smb_cli_windows_amd64.exe` (`x86_64-windows-gnu`)
- `smb_cli_windows_arm64.exe` (`aarch64-windows-gnu`)
- `smb_cli_freebsd_x86_64` (`x86_64-freebsd`)
- `smb_cli_freebsd_arm64` (`aarch64-freebsd`)
- `smb_cli_x86_64-unknown-cosmo.com` (Cosmopolitan APE, via `cosmoc++` por padrão; configurável por `-Dcosmo-cxx`)

## Uso

### Ajuda e versão

```bash
./release/bin/smb_cli help
./release/bin/smb_cli version
```

### Subir servidor autenticado (recomendado)

```bash
./release/bin/smb_cli serve \
  --share-dir /srv/smb \
  --username operador \
  --password 'troque-esta-senha' \
  --port 14445 \
  --prod-profile
```

### Smoke test local (cliente embutido)

```bash
./release/bin/smb_cli smoke-client \
  --host 127.0.0.1 \
  --port 14445 \
  --username operador \
  --password 'troque-esta-senha'
```

### Self-test de protocolo (sem rede)

```bash
./release/bin/smb_cli self-test
```

## Flags importantes de produção

- `--prod-profile`
  - força autenticação
  - exige `--share-dir` explícito
  - aplica limites mais rígidos
- `--disable-legacy-ntlm`
  - aceita apenas NTLMv2
- `--enable-signing`
  - habilita assinatura SMB2 para sessões autenticadas
- `--require-signing`
  - exige requests SMB2 assinados após autenticação
- `--strict-auth-session-flags`
  - remove compatibilidade guest nos flags de sessão autenticada
- `--read-only`
  - bloqueia escrita e disposições destrutivas
- `--max-open-files <n>`
- `--max-file-size <bytes>`
- `--timeout <segundos>`
- `--max-clients <n>`

## Qualidade

Gate local:

```bash
./quality_gate.sh
```

Esse gate executa:

- build estrito com hardening (`stack-protector`, `FORTIFY`, frame pointers) e warnings tratados como erro
- `self-test` no binário estrito
- `self-test` adicional com `ASan+UBSan`
- smoke test runtime (best effort em ambientes restritos)

QCA completo (recomendado para pré-release):

```bash
./qca.sh
```

`qca.sh` consolida:

- build `ReleaseFast` e `Debug`
- `quality_gate.sh`
- `self-test` do binário final
- validações negativas de configuração (combinações inválidas de auth/signing e credenciais)
- cenários de runtime para auth/anônimo/signing (incluindo caso negativo com cliente sem assinatura)
- interop com `smbclient` quando disponível
- relatório em `dist/qca/qca_report.txt`

Variáveis úteis do QCA:

- `QCA_REQUIRE_RUNTIME=1` para falhar quando runtime/interop não puderem ser executados
- `QCA_RUN_MATRIX=0` para reduzir tempo local (sem build cross completo)
- `QCA_RUN_INTEROP=0|1|auto` para controlar testes com `smbclient`

Interoperabilidade externa (`smbclient`):

```bash
zig build native
./interop_smbclient.sh
```

## Deploy com systemd

Templates disponíveis em `deploy/systemd/`:

1. Copiar `deploy/systemd/smb-single.service.example` para `/etc/systemd/system/smb-single.service`
2. Copiar `deploy/systemd/smb-single.env.example` para `/etc/smb-single/smb-single.env`
3. Ajustar credenciais e permissões:

```bash
chmod 600 /etc/smb-single/smb-single.env
```

4. Habilitar serviço:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now smb-single
```

## CI/CD (GitHub Actions)

Workflow: `.github/workflows/release.yml`

- Instala Zig 0.15.2
- Instala Cosmocc 4.0.2
- Roda `qca.sh` como gate de qualidade/funcionalidade (com upload do relatório)
- Executa `zig build matrix cosmo -Doptimize=ReleaseFast`
- Empacota cada target em `.tar.gz`
- Gera `SHA256SUMS.txt`
- Publica artifacts do workflow
- Em evento de `release published`, publica os arquivos da pasta `dist/` como assets da release

## Escopo de protocolo

Este projeto cobre o baseline SMB2/SMB3 descrito acima, com autenticação NTLM e opção de assinatura SMB2.

Para ambiente corporativo com requisitos avançados (por exemplo, Kerberos nativo, SMB3 encryption fim a fim e recursos completos de durable handles/leasing), execute validação de aderência de protocolo antes de adoção em produção crítica.
