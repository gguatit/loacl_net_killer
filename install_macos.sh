#!/bin/bash

# Network Device Controller - macOS 설치 스크립트

set -e

echo "========================================"
echo "  Network Device Controller 설치"
echo "  macOS"
echo "========================================"
echo ""

# 1. Homebrew 확인
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew를 찾을 수 없습니다. 먼저 설치하세요:"
    echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    exit 1
fi

# 2. Python 설치
echo "[1/4] Python3 확인..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 설치 중..."
    brew install python3
fi

# 3. pip 업그레이드
echo "[2/4] pip 업그레이드..."
python3 -m pip install --upgrade pip

# 4. 가상 환경 생성
if [ ! -d "venv" ]; then
    echo "[3/4] Python 가상 환경 생성..."
    python3 -m venv venv
    source venv/bin/activate
else
    echo "[3/4] 기존 가상 환경 사용"
    source venv/bin/activate
fi

# 5. 의존성 설치
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
echo "   - 로컬 네트워크 스캔이 제한될 수 있습니다"
echo "   - macOS 보안 설정에서 앱 권한을 확인하세요"
echo "========================================"
