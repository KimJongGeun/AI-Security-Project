# Claude Code 보안 모니터링

Claude Code를 전사적으로 도입하면서, 사용자들이 AI에 어떤 데이터를 보내고 있는지 중앙에서 모니터링할 필요가 생겼다. 특히 민감정보(주민번호, API 키 등)가 프롬프트에 포함되는 경우를 탐지하고, 위험한 명령어가 실행되는 것을 감시해야 했다.

이 프로젝트는 Claude Code의 Hook 시스템을 활용해서, **사용자 PC에 별도 소프트웨어를 설치하지 않고** 중앙 서버에서 모든 사용 내역을 수집하고 보안 분석하는 체계를 구현한 것이다.

---

## 배경

### 문제

- 개발자들이 Claude Code에 사내 코드, 고객 정보, 인증 키를 자유롭게 입력하고 있음
- 누가 언제 어떤 내용을 AI에 보냈는지 추적할 방법이 없음
- 위험한 시스템 명령어(rm -rf, curl|bash 등)가 실행될 수 있음

### 접근 방법

Claude Code는 [Hooks](https://docs.anthropic.com/en/docs/claude-code/hooks)라는 이벤트 시스템을 지원한다. 사용자가 프롬프트를 입력하거나 도구를 실행할 때마다 HTTP POST로 외부 서버에 이벤트를 전송할 수 있다.

이걸 이용하면 사용자 PC에는 설정 파일 하나만 배포하고, 나머지 보안 분석은 전부 중앙 서버에서 처리할 수 있다.

---

## 동작 방식

### 전체 흐름

```
[직원 PC]                              [중앙 서버]

Claude Code (CLI / VSCode)
    │
    ├─ 프롬프트 입력 시
    ├─ 도구 실행 전/후
    ├─ 세션 시작/종료 시
    │
    └─── HTTP POST ──────────────►  Logstash (:8080)
         (Hook 자동 전송)                │
                                       ├─ DLP 분석 (민감정보 탐지)
                                       ├─ 위험 명령어 분석
                                       │
                                       ▼
                                  Elasticsearch (저장)
                                       │
                                       ▼
                                  Kibana / Splunk (대시보드)
```

### 사용자 PC에서 일어나는 일

Claude Code는 `~/.claude/settings.json`에 정의된 Hook 설정을 읽는다. Hook 타입이 `http`이면, 이벤트가 발생할 때마다 해당 URL로 JSON을 POST 전송한다.

사용자 입장에서는 아무것도 설치할 필요가 없고, Claude Code를 쓰는 것 자체가 달라지는 건 없다. 백그라운드에서 HTTP 요청이 나갈 뿐이다.

### Hook 이벤트 종류

Claude Code는 총 27개 이상의 Hook 이벤트를 지원한다. 이 중 보안 모니터링에 필요한 핵심 6개를 선별했다.

| 이벤트 | 발생 시점 | 전송되는 주요 데이터 |
|---|---|---|
| `UserPromptSubmit` | 사용자가 프롬프트를 입력할 때 | 프롬프트 전문, 세션 ID, 작업 디렉토리 |
| `PreToolUse` | Claude가 도구를 실행하기 직전 | 도구 이름, 입력 값 (Bash 명령어 등) |
| `PostToolUse` | 도구 실행 완료 직후 | 도구 이름, 실행 결과 |
| `Stop` | Claude가 응답을 완료했을 때 | 응답 내용, 종료 사유 |
| `SessionStart` | 새 대화 세션 시작 시 | 세션 ID, 권한 모드 |
| `SessionEnd` | 세션 종료 시 | 세션 ID, transcript 경로 |

Claude Code가 전송하는 JSON 예시:

```json
{
  "session_id": "fa20abc8-53a6-4514-b926-f962ad4515b6",
  "hook_event_name": "UserPromptSubmit",
  "cwd": "/Users/hong/my-project",
  "permission_mode": "default",
  "prompt": "이 코드에서 버그를 찾아줘"
}
```

```json
{
  "session_id": "fa20abc8-53a6-4514-b926-f962ad4515b6",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "npm test"
  }
}
```

### 중앙 서버에서 일어나는 일

Logstash가 HTTP로 이벤트를 수신하면, 아래 보안 분석을 자동 수행한다.

**DLP (민감정보 탐지)**

프롬프트 텍스트에서 정규식으로 민감정보 패턴을 탐지한다.

| 탐지 항목 | 패턴 예시 | 위험도 |
|---|---|---|
| 주민등록번호 | `901010-1234567` | High |
| OpenAI API 키 | `sk-...`, `sk-proj-...` (20자 이상) | High |
| AWS Access Key | `AKIA...` (16자) | High |
| GitHub Token | `ghp_...` (36자) | High |
| Anthropic API 키 | `sk-ant-...` (90자 이상) | High |
| SSH Private Key | `-----BEGIN RSA PRIVATE KEY-----` | High |
| JWT 토큰 | `eyJ...` | High |
| 이메일 | `user@company.com` | Low |
| 전화번호(한국) | `010-1234-5678` | Low |
| 신용카드번호 | `1234-5678-9012-3456` | Low |
| 사업자등록번호 | `123-45-67890` | Low |
| 여권번호(한국) | `M12345678` | Low |

High 위험도 PII가 탐지되면 보안 알림 인덱스에 별도 기록된다.

**위험 명령어 탐지**

Bash 도구 실행 시 명령어를 분석한다.

| 위험 수준 | 명령어 |
|---|---|
| High | `rm -rf /`, `sudo rm -rf`, `curl \| bash`, `wget \| bash`, `mkfs.`, `dd if=... of=/dev/`, fork bomb, `base64 -d \| bash`, reverse shell 패턴 |
| High | 민감 파일 접근: `.env`, `id_rsa`, `.pem`, `credentials`, `passwd`, `shadow`, `.aws/credentials`, `.ssh/`, `.netrc` 등 |
| Medium | `sudo`, `chmod`, `chown`, `kill`, `systemctl`, `iptables`, `ufw` |

---

## 사용자 PC 설정

### settings.json 구조

`settings-template.json`을 `~/.claude/settings.json`으로 복사하고, 서버 주소만 변경하면 된다.

```bash
sed 's|YOUR_LOGSTASH_SERVER|security-log.company.com|g' \
  settings-template.json > ~/.claude/settings.json
```

설정 파일의 구조:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [{
          "type": "http",
          "url": "http://security-log.company.com:8080",
          "timeout": 5
        }]
      }
    ]
  }
}
```

- `matcher`: 빈 문자열이면 모든 이벤트에 매칭
- `type`: `http`이면 별도 스크립트 없이 HTTP POST로 전송
- `timeout`: 서버 응답 대기 시간 (초). 기본값은 30초. 서버가 다운되어도 Claude 사용에 영향 없음

---

## 전사 배포 방법

### 방법 1: Managed Settings (권장)

Anthropic이 공식 지원하는 전사 설정 배포 방식이다. 이 방식으로 배포하면 **직원이 설정을 삭제하거나 변경할 수 없다.**

배포 경로:
- macOS: `/Library/Application Support/Claude/managed-settings.json`
- Linux: `/etc/claude/managed-settings.json`

MDM(Jamf, Mosyle 등)으로 위 경로에 파일을 배포하면 된다. `settings-template.json`과 동일한 형식을 사용한다.

일반 `~/.claude/settings.json`과의 차이:

| 항목 | settings.json | managed-settings.json |
|---|---|---|
| 배포 위치 | 사용자 홈 디렉토리 | 시스템 경로 |
| 직원이 수정 가능 | O | **X** |
| 직원이 삭제 가능 | O | **X (root 권한 필요)** |
| 배포 방법 | 스크립트, 수동 | MDM |

### 방법 2: MDM 스크립트 배포

MDM에서 managed-settings.json을 배포하지 않고, 일반 settings.json을 배포하는 방식이다. 직원이 삭제할 수 있지만 배포가 더 간단하다.

```bash
#!/bin/bash
# MDM 배포 스크립트 (macOS)
SERVER="security-log.company.com"
SETTINGS_FILE="$HOME/.claude/settings.json"

mkdir -p "$(dirname "$SETTINGS_FILE")"

cat > "$SETTINGS_FILE" << EOF
{
  "hooks": {
    "UserPromptSubmit": [{"matcher":"","hooks":[{"type":"http","url":"http://${SERVER}:8080","timeout":5}]}],
    "PreToolUse": [{"matcher":"","hooks":[{"type":"http","url":"http://${SERVER}:8080","timeout":5}]}],
    "PostToolUse": [{"matcher":"","hooks":[{"type":"http","url":"http://${SERVER}:8080","timeout":5}]}],
    "Stop": [{"matcher":"","hooks":[{"type":"http","url":"http://${SERVER}:8080","timeout":5}]}],
    "SessionStart": [{"matcher":"","hooks":[{"type":"http","url":"http://${SERVER}:8080","timeout":5}]}],
    "SessionEnd": [{"matcher":"","hooks":[{"type":"http","url":"http://${SERVER}:8080","timeout":5}]}]
  }
}
EOF
```

### 방법 3: Ansible (Linux 환경)

```yaml
- hosts: developers
  vars:
    log_server: "security-log.company.com"
  tasks:
    - name: Claude 설정 디렉토리 생성
      file:
        path: "{{ ansible_env.HOME }}/.claude"
        state: directory

    - name: Hook 설정 배포
      template:
        src: settings-template.json.j2
        dest: "{{ ansible_env.HOME }}/.claude/settings.json"
```

---

## 서버 측 구축 (참고 구현)

`monitoring/` 폴더에 ELK Stack 기반의 참고 구현이 포함되어 있다. 실제 운영 환경에서는 Splunk 등 기존 SIEM에 맞게 수신 서버를 구축하면 된다.

### ELK PoC 구성

```
monitoring/
├── docker-compose.yml                    # Elasticsearch + Logstash + Kibana
├── elk/logstash/pipeline/
│   └── claude-audit.conf                 # 보안 분석 파이프라인 (DLP, 위험명령어)
└── kibana/
    ├── dashboard-export.ndjson           # 감사 대시보드
    └── security-alerts-dashboard.ndjson  # 보안 알림 대시보드
```

실행:

```bash
cd monitoring
docker compose up -d
```

확인:

```bash
# Logstash HTTP 수신 테스트
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"hook_event_name":"test","prompt":"hello"}'
# → "ok" 응답

# Elasticsearch 데이터 확인
curl http://localhost:9200/claude-audit-*/_count

# Kibana 대시보드
# http://localhost:5601
```

### Splunk 환경에서의 구현

Splunk를 사용하는 경우, HTTP Event Collector(HEC)로 수신할 수 있다.

단, Claude Code의 HTTP Hook은 raw JSON을 전송하고, Splunk HEC의 `/services/collector/event` 엔드포인트는 `{"event": {...}}` 래핑을 요구한다. 따라서 두 가지 방법 중 하나를 선택해야 한다.

**방법 A: `/services/collector/raw` 엔드포인트 사용**

```json
{
  "type": "http",
  "url": "https://splunk.company.com:8088/services/collector/raw?sourcetype=_json&index=claude_audit",
  "headers": {
    "Authorization": "Splunk $SPLUNK_HEC_TOKEN"
  },
  "allowedEnvVars": ["SPLUNK_HEC_TOKEN"],
  "timeout": 5
}
```

URL의 `sourcetype=_json` 파라미터로 JSON 필드가 자동 추출된다. 또는 Splunk Web에서 HEC 토큰의 기본 sourcetype을 `_json`으로 설정해도 된다.

**방법 B: 중간에 Logstash를 프록시로 사용**

Claude Code → Logstash(DLP 분석) → Splunk HEC 순서로 구성하면, DLP 분석과 Splunk 연동을 동시에 할 수 있다. 이 경우 Logstash output을 Splunk HEC로 변경하면 된다.

DLP 분석은 SPL로도 구현할 수 있다. `claude-audit.conf`의 로직을 SPL로 변환한 예시:

```spl
# 민감정보 탐지
index=claude_audit hook_event="UserPromptSubmit"
| eval has_kr_ssn=if(match(prompt, "\d{6}\s?-\s?[1-4]\d{6}"), 1, 0)
| eval has_api_key=if(match(prompt, "(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36})"), 1, 0)
| eval has_private_key=if(match(prompt, "-----BEGIN.*PRIVATE KEY-----"), 1, 0)
| where has_kr_ssn=1 OR has_api_key=1 OR has_private_key=1
| stats count by session_id, cwd

# 위험 명령어 탐지
index=claude_audit hook_event="PreToolUse" tool_name="Bash"
| eval cmd=spath(tool_input, "command")
| eval is_dangerous=if(match(cmd, "(rm\s+-rf\s+/|sudo\s+rm\s+-rf|curl.*\|.*bash|mkfs\.)"), 1, 0)
| where is_dangerous=1
```

---

## 보안 주의사항

이 프로젝트의 `monitoring/` 폴더는 **로컬 테스트용 PoC**다. 운영 환경에 그대로 쓰면 안 된다.

### 운영 환경 전환 시 필수 조치

| 항목 | PoC (현재) | 운영 환경 |
|---|---|---|
| 전송 프로토콜 | `http://` (평문) | **`https://` (TLS 필수)** |
| Logstash 인증 | 없음 (누구나 POST 가능) | API Key 또는 네트워크 ACL |
| Elasticsearch 보안 | `xpack.security.enabled=false` | **xpack.security 활성화 + 계정 인증** |
| Kibana 접근 제어 | 없음 | RBAC 또는 SSO 연동 |

프롬프트 전문이 네트워크를 타기 때문에, **HTTP 평문 전송은 운영 환경에서 절대 사용하면 안 된다.** 네트워크 스니핑 시 민감정보가 그대로 노출된다.

`settings-template.json`의 URL을 `https://`로 변경하고, Logstash HTTP input에 SSL 인증서를 설정하거나, Splunk HEC(기본 HTTPS)를 사용하면 된다.

---

## 대상 범위와 한계

### 모니터링 가능한 환경

| 환경 | 가능 여부 | 이유 |
|---|---|---|
| Claude Code CLI (터미널) | O | Hook 지원 |
| VSCode Extension | O | 동일한 settings.json 사용 |
| Claude.ai 웹/앱 | X | Hook 미지원 (브라우저 기반) |
| API 직접 호출 | X | Hook 미지원 |

### Claude.ai 웹/앱 모니터링

Claude.ai는 Hook이 적용되지 않기 때문에 네트워크 레벨에서 잡아야 한다.

- **NGFW SSL 복호화** (Palo Alto 등): `claude.ai`, `api.anthropic.com` 대상으로 Forward Proxy 설정
- **정책으로 차단**: Claude.ai 접속을 차단하고 Claude Code만 허용

### API 직접 호출 모니터링

자체 개발한 앱에서 Anthropic API를 직접 호출하는 경우, LiteLLM 같은 AI Gateway를 프록시로 두면 모든 API 트래픽을 중간에서 로깅할 수 있다.

---

## 파일 구조

```
.
├── README.md                             # 이 문서
├── settings-template.json                # 사용자 PC 배포용 설정 템플릿
├── .gitignore
└── monitoring/                           # 서버 측 참고 구현 (ELK PoC)
    ├── docker-compose.yml
    ├── elk/logstash/pipeline/
    │   └── claude-audit.conf             # DLP + 위험명령어 분석 파이프라인
    └── kibana/
        ├── dashboard-export.ndjson
        └── security-alerts-dashboard.ndjson
```

---

## 참고 자료

- [Claude Code Hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) - Hook 이벤트, 설정 방법, 핸들러 타입
- [Claude Code Managed Settings](https://code.claude.com/docs/en/settings) - MDM을 통한 전사 설정 배포
- [Elastic Stack](https://www.elastic.co/elastic-stack) - ELK 참고 구현에 사용
