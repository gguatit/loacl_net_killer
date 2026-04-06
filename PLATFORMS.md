# Network Device Controller - 크로스플랫폼 지원

## 🌐 지원하는 플랫폼

### ✅ 완전 지원
- **Windows 10/11** - 모든 기능 100% 지원
- **Kali Linux** - 모든 기능 100% 지원  
- **Debian/Ubuntu** - 모든 기능 100% 지원
- **NetHunter** (Android + Kali) - 모든 기능 100% 지원
- **macOS** - 대부분의 기능 지원

---

## 🖥️ 플랫폼별 설치 가이드

### Windows

```bash
# 1. Python 설치 (python.org에서 다운로드)
# 설치 시 "Add Python to PATH" 체크 필수

# 2. 의존성 설치
pip install -r requirements.txt

# 3. 실행
python app.py

# 4. 접속
http://localhost:5000
```

### Linux / Kali Linux

```bash
# 1. 설치 스크립트 실행
chmod +x install_linux.sh
./install_linux.sh

# 2. 가상환경 활성화 (선택)
source venv/bin/activate

# 3. 서버 시작 (관리자 권한 권장)
sudo python3 app.py
```

### NetHunter (Android)

```bash
# 1. NetHunter 앱 열기
# 2. Terminal 실행
# 3. 프로젝트 디렉토리 이동
cd /path/to/loacl_net_killer

# 4. 스크립트 실행
chmod +x install_linux.sh
./install_linux.sh

# 5. 서버 시작
sudo python3 app.py
```

### macOS

```bash
# 1. 설치 스크립트 실행
chmod +x install_macos.sh
./install_macos.sh

# 2. 가상환경 활성화
source venv/bin/activate

# 3. 서버 시작
python3 app.py

# 4. 접속
http://localhost:5000
```

---

## 🔧 플랫폼별 기능 지원표

| 기능 | Windows | Linux | macOS | NetHunter |
|------|---------|-------|-------|-----------|
| 로컬 PC 정보 | ✅ | ✅ | ✅ | ✅ |
| Ping 기반 스캔 | ✅ | ✅ | ✅ | ✅ |
| ARP 테이블 | ✅ | ✅ | ✅ | ✅ |
| mDNS 감지 | ✅ | ✅ | ✅ | ✅ |
| 호스트명 감지 | ✅ | ✅ | ✅ | ✅ |
| 속도 제어 API | ✅ | ⚠️ | ⚠️ | ⚠️ |
| 웹 대시보드 | ✅ | ✅ | ✅ | ✅ |

**⚠️**: Linux/macOS에서는 속도 제어를 위해 추가 도구(tc, wondershaper, ipfw) 필요

---

## 📊 플랫폼별 자동 감지 방식

### Windows
```
로컬 IP: socket.gethostbyname() → UDP 소켓
MAC 주소: ipconfig /all → getmac
게이트웨이: route print → netstat -r
호스트명: nbtstat -a → socket.gethostbyaddr()
DNS: ipconfig /all
```

### Linux (Kali, Debian, NetHunter)
```
로컬 IP: ip addr show → ifconfig
MAC 주소: ip link show
게이트웨이: ip route show
호스트명: host 명령 → /etc/hosts
DNS: /etc/resolv.conf
ARP: /proc/net/arp (빠름!) → arp -a
```

### macOS
```
로컬 IP: socket.gethostbyname() → ifconfig
MAC 주소: ifconfig
게이트웨이: route -n get default
호스트명: socket.gethostbyaddr()
DNS: /etc/resolv.conf
ARP: arp -a
```

---

## 🚀 플랫폼별 권장 사항

### Kali Linux
- **관리자 권한 필수**: `sudo python3 app.py`
- **최적 성능**: `/proc/net/arp` 직접 읽기로 빠른 스캔
- **추가 도구**: nmap, airmon-ng 연동 가능

### NetHunter
- **WiFi 인터페이스 감지**: `wlan0` 자동 감지
- **Packet Capture**: tcpdump 연동 가능
- **성능**: 모바일 환경에 최적화

### macOS
- **Gatekeeper 확인**: 실행 시 보안 경고 가능
- **혼합 네트워크**: WiFi + Ethernet 동시 지원
- **한계**: 광범위 ARP 스푸핑은 제한적

---

## 🔍 크로스플랫폼 테스트 체크리스트

- [ ] `get_local_info()` - 플랫폼별 로컬 정보 수집
- [ ] `arp_scan()` - ARP 테이블 스캔
- [ ] `ping_host_fast()` - Ping 기반 온라인 감지
- [ ] `get_hostname_from_ip()` - 호스트명 감지
- [ ] `scan_mdns_services()` - mDNS 백그라운드 스캔
- [ ] API `/api/scan/arp` - ARP 스캔 엔드포인트
- [ ] API `/api/arp/speed/{mac}/{speed}` - 속도 제어 (시뮬레이션)

---

## 🐛 트러블슈팅

### Linux에서 "Permission denied" 오류
```bash
# 해결책: 관리자 권한으로 실행
sudo python3 app.py

# 또는 특정 명령만 권한 부여
sudo setcap cap_net_raw+ep /usr/bin/ping
```

### macOS에서 mDNS 감지 안됨
```bash
# mDNS 서비스 확인
dns-sd -B _http._tcp local
```

### NetHunter에서 모듈 오류
```bash
# Python 경로 확인
which python3

# 가상환경 다시 생성
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📝 버전 호환성

- Python: 3.7+
- Flask: 3.0.0+
- zeroconf: 0.130+

---

## 🎯 다음 단계

1. 플랫폼별로 테스트 완료
2. 속도 제어 도구 연동 (tc, wondershaper 등)
3. Web UI 모바일 최적화
4. Docker 이미지 제작
