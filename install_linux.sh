#!/bin/bash

# Network Device Controller - Kali Linux / NetHunter 설치 스크립트
# 이 스크립트는 Kali Linux, NetHunter, Debian 기반 시스템에서 작동합니다

set -e

echo "========================================"
echo "  Network Device Controller 설치"
echo "  Kali Linux / NetHunter / Linux"
echo "========================================"
echo ""

# 1. 시스템 패키지 체크
echo "[1/4] 필수 패키지 확인 중..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3를 찾을 수 없습니다. 먼저 설치하세요:"
    echo "   sudo apt update && sudo apt install -y python3 python3-pip"
    exit 1
fi

# 2. pip 설치
echo "[2/4] pip 업그레이드..."
python3 -m pip install --upgrade pip

# 3. 가상 환경 생성 (선택사항이지만 권장)
if [ ! -d "venv" ]; then
    echo "[3/4] Python 가상 환경 생성..."
    python3 -m venv venv
    source venv/bin/activate
else
    echo "[3/4] 기존 가상 환경 사용 (venv 디렉토리 발견)"
    source venv/bin/activate
fi

# 4. 의존성 설치
echo "[4/4] Python 의존성 설치..."
pip install -r requirements.txt

echo ""
echo "========================================"
echo "✅ 설치 완료!"
echo "========================================"
echo ""
echo "📋 실행 방법:"
echo "   1. 가상환경 활성화:"
echo "      source venv/bin/activate"
echo ""
echo "   2. 서버 시작:"
echo "      python3 app.py"
echo ""
echo "   3. 브라우저에서 접속:"
echo "      http://localhost:5000"
echo ""
echo "📝 참고사항:"
echo "   - 네트워크 스캔은 root 권한이 필요할 수 있습니다:"
echo "     sudo python3 app.py"
echo ""
echo "   - NetHunter에서 사용:"
echo "     kali> python3 app.py"
echo "========================================"
