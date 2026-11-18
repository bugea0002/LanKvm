# LanKvm

Windows 유선 데스크탑(Host)과 와이파이 노트북(Client) 간 **마우스 · 키보드 · 클립보드**를 저지연으로 공유하는 C# (.NET 8) 소프트웨어 KVM입니다.

## 주요 기능
* **이중 NAT / 다른 서브넷 대응:** 노트북(Client)이 데스크탑(Host)으로 먼저 접속하며, `UDP_HELLO` 홀 유지 및 자동 TCP 폴백을 지원합니다.
* **저지연 입력 공유:** 데스크탑 Raw Input(`WM_INPUT`) + 6ms 마우스 델타 병합(Coalescing) + UDP(AES-256-GCM) 전송 및 `PerMonitorV2` DPI 지원.
* **1회 페어링 & 무인 자동 연결:** 최초 1회 PIN 페어링 후 256비트 기기 토큰 발급(Client: Windows DPAPI 암호화 저장, Host: SHA-256 해시 저장), 부팅 시 트레이(`--minimized`) 자동 실행 지원.
* **클립보드 양방향 동기화:** 텍스트 및 이미지(PNG) 동기화, SHA-256 루프 방지.
* **안전장치:** 하트비트 타임아웃 자동 복구 및 긴급 탈출 단축키(`Ctrl + Alt + Esc`).
* **듀얼 자동 업데이트:** 인증된 Host → Client LAN 직접 동기화 또는 GitHub Releases(`LanKvm.exe` + `LanKvm.exe.sha256` 검증) 지원.

## 보안 설계
* **TLS + 인증서 지문 바인딩 (TOFU):** 자체 서명 ECDSA P-256 인증서와 지문 바인딩 HMAC으로 중간자 공격(MITM) 차단.
* **사설망 전용 제한:** 앱 레벨(`Loopback` / RFC 1918 사설 IPv4만 허용) 및 방화벽 스크립트 모두 공인 IP 접근을 차단합니다.
* **PIN 브루트포스 방어:** 1대 이상 등록 시 PIN 페어링 자동 잠금, 5회 실패 시 60초 차단.
* **실행 시 저장되는 개인 설정/인증서:** `%AppData%\LanKvm`에 저장되며 소스 코드 저장소에 포함되지 않습니다.

## 빌드 및 실행
```powershell
dotnet build LanKvm.sln -c Release
dotnet test LanKvm.sln -c Release --no-build
dotnet publish src/LanKvm.App/LanKvm.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ./dist
```
