# Network Device Controller

로컬 네트워크 스캔 및 장치 제어 대시보드

## Requirements

- Python 3.8+
- Flask
- Windows OS

## Installation

```bash
pip install flask
```

## Usage

```bash
python app.py
```

브라우저에서 접속: `http://localhost:5000`

## Linux One-Click Run

리눅스/NetHunter에서 `venv 생성 + pip 설치 + 서버 실행`을 한 번에 수행합니다.

```bash
chmod +x start_all_linux.sh
./start_all_linux.sh
```

제어 API까지 같이 실행하려면:

```bash
export CONTROL_API_COMMAND="여기에_제어API_실행명령"
./start_all_linux.sh
```

GUI만 실행하려면:

```bash
chmod +x start_gui_only_linux.sh
./start_gui_only_linux.sh
```

## Features

### Network Scan Tab
- 로컬 PC 정보 표시 (Hostname, IP, MAC, Gateway, OS)
- 네트워크 스캔 (Ping 기반)
- ARP 테이블 로드
- 장치 정보: IP, Hostname, MAC, Vendor, OS 추정, TTL

### API Devices Tab
- 인터넷 차단/속도 제한
- Lag Switch (Outgoing/Incoming)
- 게임 잠금 (PS4, PS5, Xbox, RD2, GoodSport, DayZ, InnerPeace)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/api/local-info` | GET | 로컬 PC 정보 |
| `/api/scan/start` | GET | 네트워크 스캔 시작 |
| `/api/scan/status` | GET | 스캔 상태 확인 |
| `/api/scan/arp` | GET | ARP 테이블 로드 |
| `/api/devices` | GET | API 장치 목록 |
| `/api/control/{action}/{mac}/{value}` | GET | 장치 제어 |

## Control Actions

| Action | Description |
|--------|-------------|
| `speed/{mac}/0` | 인터넷 차단 |
| `speed/{mac}/unlimit` | 인터넷 복원 |
| `speed/{mac}/{kb}` | 속도 제한 (KB/s) |
| `lagout/{mac}/{ms}` | Outgoing 지연 (ms) |
| `lagin/{mac}/{ms}` | Incoming 지연 (ms) |
| `ps4lock/{mac}/on` | PS4 잠금 On |
| `ps4lock/{mac}/off` | PS4 잠금 Off |

## Project Structure

```
.
├── app.py              # Flask 서버
├── scanner.py           # 네트워크 스캔 모듈
├── templates/
│   └── index.html      # 프론트엔드
└── 새 텍스트 문서.txt   # 네트워크 데이터
```

## Notes

- Gateway와 MAC 주소는 자동으로 감지됩니다
- OS 추정은 TTL 값 기반으로 추정합니다
- Vendor는 MAC 주소의 OUI를 기반으로 표시됩니다
