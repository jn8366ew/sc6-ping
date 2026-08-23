#!/usr/bin/env python3
"""
SoulCalibur VI P2P 상대 지연 모니터

동작 원리:
  1. SC6/스팀이 쥐고 있는 UDP 포트만 골라 계속 캡처한다.
  2. 스팀 릴레이(Valve 대역)를 걸러내고 실제 상대 IP를 추정한다.
  3. 두 가지를 동시에 잰다:
       - 능동: ICMP 핑으로 왕복 시간(RTT) → 프레임 지연으로 환산
       - 수동: 상대 패킷의 도착 간격 → 지터와 '프레임 갭'
  4. 콘솔과 RTSS 오버레이(게임 화면)에 표시한다.

SC6는 딜레이 기반 넷코드라 늦게 온 패킷을 되감아 보정하지 못하고 그냥
기다린다. 그래서 평균 핑보다 '도착 간격이 튀는 순간'이 체감을 좌우한다.
실측상 상대 패킷은 초당 65개, 즉 60fps 프레임당 1개꼴로 들어오므로
도착 간격이 2프레임을 넘으면 그만큼 게임이 멈춰 기다렸다는 뜻이다.

필요 조건:
  1. Npcap 설치 (https://npcap.com)
       * "Install Npcap in WinPcap API-compatible Mode"           → 체크
       * "Restrict Npcap driver's access to Administrators only"  → 해제
         해제하면 관리자 권한 없이 실행할 수 있다.
         체크한 채로 설치했다면 관리자 터미널에서 실행해야 한다.
  2. (선택) RTSS 설치 — 게임 화면 오버레이용. 없으면 콘솔만 쓴다.
       C:\\Program Files (x86)\\MSI Afterburner\\Redist\\RTSSSetup.exe
  3. uv sync
  4. uv run monitor.py

주의: 이 도구는 '내 연결 품질 확인' 용도입니다. 상대 IP는 개인정보이니
      저장하거나 외부에 공유하지 마세요.
"""

import re
import sys
import time
import ctypes
import shutil
import socket
import platform
import ipaddress
import threading
import statistics
import subprocess
import collections
import unicodedata

import psutil
from scapy.all import AsyncSniffer, IP, UDP

# ----------------------------- 설정 -----------------------------
GAME_FPS = 60  # SC6는 60fps → 1프레임 ≈ 16.67ms
FRAME_MS = 1000.0 / GAME_FPS

IS_WINDOWS = platform.system().lower().startswith("win")

# 측정 창과 갱신 주기 — 셋이 서로 독립이다.
JITTER_WINDOW = 2.0  # 도착 간격 통계를 내는 구간 (초). 2초 ≈ 130샘플
# 중앙값·p95를 낼 최소 간격 표본 수. 이보다 적으면 통계를 내지 않고
# '모름'으로 표시한다 — 0으로 두면 화면에서 '측정값이 0'과 구별되지 않는다.
MIN_GAP_SAMPLES = 5
DISPLAY_INTERVAL = 0.25  # OSD 갱신 (4Hz). 이보다 빠르면 사람이 못 읽는다
LOG_INTERVAL = 2.0  # 콘솔 로그 한 줄
RESELECT_SECONDS = 5.0  # 상대 재선정 / 포트 재열거 주기
POLL_INTERVAL = 0.2  # 블로킹을 쪼개는 단위 = Ctrl+C 응답 시간

# 상대 후보로 새로 인정할 최소 패킷 속도 (pkt/s).
# 실측: 실제 대전은 132pkt/s(프레임당 1패킷, ↑↓ 1:1), 매칭 단계의 잡담은
# 4~18pkt/s. 예전 값 5.0은 잡담을 전부 통과시켜서 대전이 아닌 IP가 상대로
# 뽑히고, 여러 IP가 번갈아 뽑히며 핑 이력이 계속 리셋됐다.
MIN_RATE = 50.0
# 이미 고른 상대를 유지할 최소 속도. 132pkt/s가 순간 흔들려 MIN_RATE 아래로
# 떨어질 때마다 상대를 놓으면 EMA·핑 이력·tracert 이력이 통째로 리셋된다.
# 새로 잡을 때는 엄격하게, 놓을 때는 느슨하게 (히스테리시스).
KEEP_RATE = MIN_RATE / 2
PROBE_CANDIDATES = 3  # 상대 재선정 때 찔러볼 상위 후보 수
PROBE_CACHE_TTL = 60.0  # 후보 ICMP 프로브 결과를 재사용하는 기간 (초)

PING_INTERVAL = 1.0  # 핑 재는 주기 (초)
PING_ALPHA = 0.3  # EMA 계수. 약 2초에 수렴한다
PING_HISTORY = 10.0  # min/max/손실률을 내는 구간 (초)

# TTL 폴백용 tracert 설정. 최악 시간 = 홉 × 프로브 3발 × 타임아웃.
# 예전 값(20홉, 400ms)은 막힌 경로에서 24초가 걸렸다. 12홉이면 14초다.
# 국내 상대는 대개 12홉 안에 들고, 더 먼 상대라도 결과는 어차피 '하한'이라
# 경로 중간에서 끊어도 값의 성격은 그대로다.
TRACE_MAX_HOPS = 12
TRACE_PROBE_MS = 400
TRACE_CACHE_SIZE = 32  # IP별 추적 결과를 기억할 개수

# 도착 간격이 중앙값의 이 배를 넘으면 '프레임 갭'으로 센다. 프레임당 1패킷이
# 들어오는 구조라 2배 = 프레임 하나 분량이 통째로 비었다는 뜻이다.
FRAME_GAP_FACTOR = 2.0

# BPF가 비대해지지 않게 자르는 상한. 포트를 빠뜨리면 상대를 통째로 놓치므로
# (P2P 소켓은 대개 49152번 이상의 임시 포트다) 넉넉하게 잡는다.
#
# 실측(compile_filter로 bf_len을 직접 셈): 60포트 197명령, 120포트 490,
# 250포트 1269. 포트당 3~5명령으로 libpcap 한도(BPF_MAXINSNS=4096)에서 멀다.
# 예전 주석의 '포트당 10개'는 과대 추정이었다. 실측 포트 수가 58까지 갔으므로
# 200이면 3배 넘는 여유가 생긴다(약 1000명령, 한도의 25%).
MAX_FILTER_PORTS = 200

GAME_PROCESS = "SoulcaliburVI.exe"
# 스팀 네트워킹은 게임 프로세스가 아니라 스팀 클라이언트 소켓을 경유할 수도
# 있어서 둘 다 본다. 어느 쪽이 P2P 소켓을 쥐는지는 대전 중 실측으로 확인한다.
NET_OWNER_PROCESSES = [GAME_PROCESS, "steam.exe"]

# 게임 소유 포트를 못 알아냈을 때만 쓰는 폴백. 게임 P2P가 절대 쓰지 않는
# 서비스 포트를 걸러낸다. 특히 443/UDP(QUIC)는 크롬 유튜브 스트리밍이
# 초당 170패킷씩 쏟아내서 상대보다 트래픽이 많다.
#
# 주의: 스팀 릴레이(SDR)는 제한적인 망에서 443/UDP를 쓰기도 한다. 하지만
#       릴레이는 어차피 VALVE_NETWORKS로 걸러내므로 잃는 게 없다.
NOISE_PORTS = [443, 53, 123, 80]  # QUIC, DNS, NTP, HTTP
FALLBACK_BPF = "udp and " + " and ".join(f"not port {p}" for p in NOISE_PORTS)

# Valve / Steam Datagram Relay (AS32590).
# SC6는 상대와 직결(P2P)하면서 동시에 스팀 릴레이로도 같은 스트림을 흘린다.
# 릴레이 쪽 패킷이 근소하게 많을 때가 있어 그냥 두면 상대 대신 릴레이가 뽑히는데,
# 릴레이는 ICMP를 100% 드롭하므로 "핑 측정 실패"만 계속 뜬다. 아예 후보에서 뺀다.
# 출처: RIPEstat AS32590 announced prefixes (실측 확인: 146.66.152.0/23 = Valve, LU)
VALVE_NETWORKS = [
    "45.121.184.0/22",
    "103.10.124.0/23",
    "103.28.54.0/23",
    "146.66.152.0/21",
    "155.133.224.0/19",
    "162.254.192.0/21",
    "185.25.180.0/22",
    "192.69.96.0/22",
    "205.196.6.0/24",
    "208.64.200.0/22",
    "208.78.164.0/22",
]

# 게임과 무관한, 내 PC의 다른 앱이 내는 UDP 트래픽.
# 여기 없는 노이즈가 잡히면 이 목록에 추가하세요.
OTHER_NOISE_NETWORKS = [
    "160.79.104.0/21",  # Anthropic (Claude Code ↔ API, QUIC)
]

_VALVE_NETS = [ipaddress.ip_network(n) for n in VALVE_NETWORKS]
_EXCLUDE_NETS = _VALVE_NETS + [ipaddress.ip_network(n) for n in OTHER_NOISE_NETWORKS]


# ---------------------- 게임 프로세스 추적 ----------------------
def find_processes() -> dict[str, list[psutil.Process]]:
    """NET_OWNER_PROCESSES에 해당하는 실행 중 프로세스를 이름별로 모은다."""
    wanted = {name.lower(): name for name in NET_OWNER_PROCESSES}
    found: dict[str, list[psutil.Process]] = {n: [] for n in NET_OWNER_PROCESSES}
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info["name"] or "").lower()
        except psutil.Error:
            continue
        if name in wanted:
            found[wanted[name]].append(proc)
    return found


def udp_ports_of(procs: list[psutil.Process]) -> list[int]:
    """주어진 프로세스들이 쥐고 있는 UDP 로컬 포트.

    프로세스마다 조회하지 않고 시스템 전체 테이블을 한 번만 읽어 PID로 거른다.
    권한이 부족하면 빈 리스트를 돌려주고 호출부가 폴백하도록 둔다.
    """
    pids = {p.pid for p in procs}
    if not pids:
        return []
    try:
        conns = psutil.net_connections(kind="udp")
    except (psutil.AccessDenied, psutil.Error, PermissionError, OSError):
        return []

    ports = {c.laddr.port for c in conns if c.pid in pids and c.laddr}
    return sorted(ports)


class PortSet:
    """세션 동안 본 게임 소유 UDP 포트를 합집합으로 누적한다.

    psutil이 주는 목록은 그 순간의 스냅샷이라 요동친다 (실측 추이:
    3→7→9→19→3→47→58). 그때마다 BPF를 다시 만들면 스니퍼를 껐다 켜게 되고,
    재시작하는 그 순간의 패킷을 통째로 놓친다. 16.6ms 간격을 재는 도구가
    몇백 ms를 눈감는 셈이라 지터·갭이 실제보다 나쁘게 나온다.

    그래서 한 번 본 포트는 계속 지켜본다. 목록은 늘기만 하므로 스니퍼 재시작은
    '새 포트가 처음 보일 때'로 한정되고, 포트가 자리를 잡으면 곧 멈춘다.

    상한에 걸리면 가장 오래 못 본 포트부터 버린다(LRU). 지금 열려 있는 포트는
    매 주기 갱신되므로 절대 밀려나지 않는다.
    """

    def __init__(self, limit: int = MAX_FILTER_PORTS):
        self.limit = limit
        # 값은 안 쓴다. 최근 본 순서만 필요해서 OrderedDict를 쓴다.
        self._seen: collections.OrderedDict[int, None] = collections.OrderedDict()
        self.dropped = 0  # 상한 때문에 버린 포트 수 (조용히 자르지 않으려고 센다)

    def update(self, ports: list[int]) -> list[int]:
        """지금 열려 있는 포트를 반영하고, 감시할 포트 전체를 돌려준다.

        빈 목록이 와도 누적분을 버리지 않는다. psutil.net_connections()는
        일시적인 권한 오류로 빈 리스트를 줄 수 있는데, 그때마다 폴백 필터로
        떨어지면 오히려 캡처가 넓어졌다 좁아졌다 한다.
        """
        for port in ports:
            self._seen.pop(port, None)  # 이미 있으면 맨 뒤로 옮긴다
            self._seen[port] = None
        while len(self._seen) > self.limit:
            self._seen.popitem(last=False)  # 가장 오래 못 본 포트
            self.dropped += 1
        return sorted(self._seen)


def build_filter(ports: list[int]) -> str:
    """게임이 쥔 포트만 잡는 BPF. 포트를 모르면 폴백 필터를 쓴다."""
    if not ports:
        return FALLBACK_BPF
    clause = " or ".join(f"port {p}" for p in ports[:MAX_FILTER_PORTS])
    return f"udp and ({clause})"


# ------------------------- 유틸 함수 ---------------------------
def get_local_ip() -> str:
    """외부로 나가는 기본 로컬 IP를 알아낸다 (제외용)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # 실제로 패킷을 보내지는 않음
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def is_valve_relay(ip: str) -> bool:
    """스팀 릴레이 IP인지 (상대가 아니라 중계 서버)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _VALVE_NETS)


def is_ignorable(ip: str, local_ip: str) -> bool:
    """상대 후보에서 제외할 IP인지 판단."""
    if ip == local_ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        # 사설망, 루프백, 멀티캐스트, 링크로컬 등은 제외
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_link_local
        ):
            return True
    except ValueError:
        return True
    return any(addr in net for net in _EXCLUDE_NETS)


def ms_to_frames(ms: float) -> float:
    """지연(ms)을 프레임으로 환산."""
    return ms / FRAME_MS


def display_width(text: str) -> int:
    """터미널에서 차지하는 칸 수.

    한글은 한 글자가 두 칸이라 len()으로는 폭을 알 수 없다. 'A'(ambiguous)로
    분류된 →·↑·↓ 같은 기호도 CJK 코드페이지(cp949)에서는 두 칸으로 그려지므로
    같이 두 칸으로 센다. 넉넉히 잡아 틀리는 쪽이 안전하다 — 조금 일찍 자를 뿐,
    줄이 넘쳐 다음 줄과 엉키지는 않는다.
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WFA" else 1 for c in text)


def fit_width(text: str, columns: int | None = None) -> str:
    """터미널 폭을 넘으면 자른다.

    PowerShell에서 한 줄이 폭을 넘으면 다음 줄로 접히는데, 그 상태에서 다음
    출력이 겹치면 '...s (↑4 8pkt/s (↑4 ↓4)' 처럼 글자가 섞여 깨진다. 애초에
    넘기지 않는 게 유일하게 확실한 방법이다.
    """
    if columns is None:
        # 파이프로 넘길 때(Tee-Object)는 폭을 알 수 없어 fallback을 쓴다.
        columns = shutil.get_terminal_size(fallback=(120, 25)).columns
    limit = columns - 1  # 마지막 칸까지 채우면 터미널이 줄을 하나 더 넘긴다
    if limit <= 0 or display_width(text) <= limit:
        return text

    out: list[str] = []
    used = 0
    for c in text:
        w = 2 if unicodedata.east_asian_width(c) in "WFA" else 1
        if used + w > limit - 2:  # 말줄임표 자리 두 칸을 남긴다
            break
        out.append(c)
        used += w
    return "".join(out) + "…"


def match_console_encoding() -> None:
    """파이프로 내보낼 때 콘솔 코드페이지에 맞춰 쓴다.

    콘솔에 직접 쓸 때는 파이썬이 WriteConsoleW로 유니코드를 그대로
    넘겨서 인코딩을 안 탄다. 그런데 `| Tee-Object` 처럼 파이프를 물리면
    바이트로 나가고, PowerShell은 그걸 [Console]::OutputEncoding
    (= 콘솔 코드페이지, 한국어 Windows는 949)으로 되읽는다.

    이 PC는 PYTHONUTF8=1이 잡혀 있어 파이썬이 UTF-8로 쓰는데 콘솔은
    949라 서로 어긋난다. 실측: `간격 16.6ms`가 `媛꾧꺽 16.6ms`로 찍혔다.
    숫자만 ASCII라 멀쩡하게 남고 한글과 →↑↓가 전부 깨졌다.

    cp949에는 →↑↓…가 전부 있다. 다만 em dash(—, U+2014)와 en dash(–)는
    없으므로 출력 문자열에서는 horizontal bar(―, U+2015)를 쓴다. 폭 계산은
    둘 다 'A'로 같아서 fit_width() 결과가 달라지지 않는다.

    그래도 errors="replace"를 둔다 ― 로그 한 글자 때문에 측정이 죽으면 안 된다.
    """
    if not IS_WINDOWS:
        return
    try:
        cp = ctypes.windll.kernel32.GetConsoleOutputCP()
    except Exception:
        return  # 콘솔이 없는 환경. 그대로 둔다
    if not cp:
        return
    for stream in (sys.stdout, sys.stderr):
        # isatty()면 이미 WriteConsoleW라 건드릴 이유가 없다.
        if stream is None or stream.isatty():
            continue
        try:
            # line_buffering도 같이 켠다. 파이프에 물리면 파이썬은 8KB 블록
            # 버퍼링을 쓰는데, 2초에 한 줄(약 100바이트) 내는 도구라 화면이
            # 2분 넘게 밀린다. 실시간으로 보려고 만든 물건이 그러면 안 된다.
            stream.reconfigure(
                encoding=f"cp{cp}", errors="replace", line_buffering=True
            )
        except Exception:
            pass  # 못 바꿔도 측정은 돌아간다


# --------------------- 수동 측정: 도착 간격 ---------------------
class Flow:
    """한 IP에 대한 최근 트래픽 통계 스냅샷."""

    def __init__(self, ip, up, down, gaps, window):
        self.ip = ip
        self.up = up
        self.down = down
        self.count = up + down
        self.window = window
        self.rate = self.count / window if window else 0.0

        # 표본이 몇 개였는지 남긴다. 화면에서 '아직 모름'과 '재보니 0'을
        # 구별하려면 이 값이 필요하다.
        self.gap_samples = len(gaps)
        self.sampled = self.gap_samples >= MIN_GAP_SAMPLES

        if self.sampled:
            ordered = sorted(gaps)
            self.median_gap = statistics.median(ordered)
            self.p95_gap = ordered[min(int(len(ordered) * 0.95), len(ordered) - 1)]
            # 표준편차 대신 백분위 차를 쓴다. 스파이크 하나에 값이 통째로
            # 흔들리지 않아서 화면에 띄웠을 때 읽기 낫다.
            self.jitter = self.p95_gap - self.median_gap

            # 임계값에 바닥을 둔다. 다운로드처럼 패킷이 뭉쳐 오는 스트림은
            # 중앙값이 0에 가까워지는데, 그러면 threshold도 0이 되어 모든
            # 간격이 '갭'으로 잡힌다. 한 프레임 안에 도착했으면 프레임이
            # 굶은 게 아니므로 FRAME_MS 미만은 애초에 갭이 아니다.
            threshold = max(self.median_gap * FRAME_GAP_FACTOR, FRAME_MS)
            self.frame_gaps = sum(1 for g in gaps if g > threshold)
            self.gap_rate = self.frame_gaps / window if window else 0.0
            self.worst_gap = ordered[-1]
            # 프레임당 1패킷 구조일 때만 '프레임 갭'이 의미를 갖는다.
            # 그 밖의 스트림에서는 이 수치를 표시하지 않는다.
            self.frame_paced = 0.5 * FRAME_MS <= self.median_gap <= 2.0 * FRAME_MS
        else:
            # 0은 '측정하지 않았다'는 뜻이다. 값으로 읽으면 안 된다 —
            # 표시하는 쪽은 반드시 self.sampled를 먼저 본다.
            self.median_gap = self.p95_gap = self.jitter = 0.0
            self.frame_gaps = 0
            self.gap_rate = 0.0
            self.worst_gap = 0.0
            self.frame_paced = False


class TrafficWindow:
    """패킷 도착 시각을 IP별로 굴리며 보관한다.

    캡처 스레드가 쓰고 메인 스레드가 읽으므로 락을 건다. 초당 130개 수준이라
    락 경합은 문제되지 않는다.
    """

    def __init__(self, window: float = JITTER_WINDOW):
        self.window = window
        self._lock = threading.Lock()
        self._inbound: dict[str, collections.deque] = collections.defaultdict(
            collections.deque
        )
        self._outbound: dict[str, collections.deque] = collections.defaultdict(
            collections.deque
        )
        self._relay: dict[str, collections.deque] = collections.defaultdict(
            collections.deque
        )

    def add(self, ip: str, t: float, outbound: bool, relay: bool = False) -> None:
        with self._lock:
            if relay:
                self._relay[ip].append(t)
            elif outbound:
                self._outbound[ip].append(t)
            else:
                self._inbound[ip].append(t)

    @staticmethod
    def _trim(dq: collections.deque, cutoff: float) -> None:
        while dq and dq[0] < cutoff:
            dq.popleft()

    def snapshot(self, now: float) -> tuple[dict[str, Flow], float]:
        """(IP -> Flow, 릴레이 패킷 속도)를 돌려준다."""
        cutoff = now - self.window
        flows = {}
        with self._lock:
            for table in (self._inbound, self._outbound, self._relay):
                for dq in table.values():
                    self._trim(dq, cutoff)

            ips = set(self._inbound) | set(self._outbound)
            for ip in ips:
                arrivals = list(self._inbound[ip])
                up = len(self._outbound[ip])
                if not arrivals and not up:
                    continue
                # 간격은 '들어오는' 패킷만 본다. 내보내는 쪽은 내 게임의 프레임
                # 루프가 정하는 값이라 회선 상태와 무관하다.
                gaps = [
                    1000.0 * (b - a) for a, b in zip(arrivals, arrivals[1:])
                ]
                flows[ip] = Flow(ip, up, len(arrivals), gaps, self.window)

            relay_count = sum(len(dq) for dq in self._relay.values())

        return flows, relay_count / self.window if self.window else 0.0

    def forget(self, keep: set[str]) -> None:
        """더는 안 보이는 IP의 버퍼를 버린다 (장시간 구동 시 누수 방지)."""
        with self._lock:
            for table in (self._inbound, self._outbound, self._relay):
                for ip in [k for k, v in table.items() if not v and k not in keep]:
                    del table[ip]


# --------------------- 능동 측정: ICMP 핑 ----------------------
def _console_encoding() -> str:
    """ping이 출력에 쓰는 인코딩. 한글 Windows는 cp949, 영문은 cp437."""
    if IS_WINDOWS:
        try:
            return "cp" + str(ctypes.windll.kernel32.GetOEMCP())
        except Exception:
            return "cp437"
    return "utf-8"


# "시간=23ms" / "time=23ms" / "time<1ms" / "time=23.4 ms" 전부 커버.
# 숫자와 'ms'는 어느 로케일에서나 ASCII라 언어와 무관하게 잡힌다.
_RTT_RE = re.compile(r"([\d.]+)\s*ms")


def ping_once(ip: str, stop: threading.Event | None = None) -> float | None:
    """ICMP 한 발을 쏘고 RTT(ms)를 돌려준다. 응답이 없으면 None."""
    count_flag = "-n" if IS_WINDOWS else "-c"
    # 타임아웃: Windows는 -w(ms), 그 외는 -W(초)
    timeout_flag, timeout_val = ("-w", "1000") if IS_WINDOWS else ("-W", "1")
    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, ip]

    # subprocess.run()을 쓰면 Ctrl+C가 와도 자식이 끝날 때까지 3초쯤 붙잡혀
    # 있는다. 직접 띄우고 짧게 쪼개 폴링하면 POLL_INTERVAL 안에 빠져나온다.
    # text=True도 쓰지 않는다 — ping의 cp949 출력을 UTF-8로 풀려다 리더
    # 스레드가 UnicodeDecodeError로 죽고 stdout이 None이 되기 때문.
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
    except Exception:
        return None

    deadline = time.monotonic() + 3
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline or (stop and stop.is_set()):
                return None
            time.sleep(POLL_INTERVAL)
        raw = proc.stdout.read() if proc.stdout else b""
    finally:
        # 인터럽트로 빠져나갈 때도 ping.exe를 남기지 않는다.
        if proc.poll() is None:
            proc.kill()
        if proc.stdout:
            proc.stdout.close()
        proc.wait()

    out = raw.decode(_console_encoding(), errors="replace")

    # 응답 줄만 고른다. 요약 줄에도 ms가 붙어 나오므로 그걸 같이 세면 표본이
    # 중복된다. 'TTL='(Windows) / 'ttl='(Linux·macOS)은 응답 줄에만 있고
    # 로케일과 무관하게 ASCII다.
    for line in out.splitlines():
        if "ttl=" not in line.lower():
            continue
        m = _RTT_RE.search(line)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    return None


_HOP_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*$")


class TraceHop:
    """경로상 응답한 마지막 홉."""

    def __init__(self, ip: str, hop: int, dark_after: int, truncated: bool = False):
        self.ip = ip
        self.hop = hop
        self.dark_after = dark_after  # 이 홉 뒤로 조용했던 홉 수
        # 홉 한도에 걸려 끊긴 추적인지. 목적지가 얼마나 더 남았는지 알 수 없으므로
        # 안내 문구에 밝힌다 — 값 자체는 여전히 하한이라 버리지는 않는다.
        self.truncated = truncated

    @property
    def weak(self) -> bool:
        """추정치를 믿기 어려운 정도.

        경로가 일찍 끊기면 (예: 4홉에서 막히고 그 뒤 16홉이 조용) 이 홉까지의
        RTT는 목적지와 아무 상관이 없다. 실제로 룩셈부르크의 Valve 릴레이를
        추적하니 국내 ISP 4홉(2ms)에서 끊겼다 — 실제 RTT는 250ms대다.
        """
        return self.dark_after > 3


def trace_last_hop(ip: str, stop: threading.Event | None = None) -> TraceHop | None:
    """응답하는 가장 먼 홉을 찾는다.

    상대가 ICMP echo를 막아도 경로상 라우터는 TTL 만료를 돌려주는 경우가 많다.
    그 홉까지의 RTT는 실제 RTT의 '하한'이 된다 — 정확한 값이 아니다.
    """
    # -d 없이 돌리면 홉마다 역DNS 조회로 수 초씩 잡아먹는다.
    cmd = [
        "tracert", "-d",
        "-w", str(TRACE_PROBE_MS),
        "-h", str(TRACE_MAX_HOPS),
        ip,
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
    except Exception:
        return None

    # 최악 시간에 여유를 조금 얹는다 (12홉 × 3발 × 0.4s ≈ 14초).
    deadline = time.monotonic() + TRACE_MAX_HOPS * 3 * TRACE_PROBE_MS / 1000.0 + 6
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline or (stop and stop.is_set()):
                return None
            time.sleep(POLL_INTERVAL)
        raw = proc.stdout.read() if proc.stdout else b""
    finally:
        if proc.poll() is None:
            proc.kill()
        if proc.stdout:
            proc.stdout.close()
        proc.wait()

    out = raw.decode(_console_encoding(), errors="replace")

    last: TraceHop | None = None
    hop_index = 0
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped or not stripped[0].isdigit():
            continue
        hop_index += 1
        m = _HOP_IP_RE.search(stripped)
        if m and m.group(1) != ip:
            last = TraceHop(m.group(1), hop_index, 0)
        elif m and m.group(1) == ip:
            # 목적지가 직접 응답했다면 폴백이 필요 없다.
            return None

    if last is None:
        return None
    last.dark_after = hop_index - last.hop
    # 목적지에 닿기 전에 홉 한도로 끊겼다면 그 사실을 남긴다.
    last.truncated = hop_index >= TRACE_MAX_HOPS
    return last


class Pinger(threading.Thread):
    """상대에게 계속 핑을 쏘는 데몬 스레드.

    메인 루프를 막지 않는 게 요점이다. Windows ping.exe는 요청 사이에 1초를
    강제로 쉬기 때문에, 예전처럼 메인에서 -n 3으로 부르면 사이클마다 2초를
    통째로 잡아먹었다.
    """

    FAILS_BEFORE_TRACE = 3  # 이만큼 연속 무응답이면 폴백 경로를 찾는다

    def __init__(self):
        super().__init__(daemon=True, name="Pinger")
        # 이름이 _stop이면 안 된다 — threading.Thread._stop은 실제로 존재하는
        # 내부 메서드라, 덮어쓰면 Thread.join()이 'Event object is not callable'로
        # 터진다. 지금은 데몬이라 join을 안 해서 드러나지 않았을 뿐이다.
        self._stopped = threading.Event()
        self._lock = threading.Lock()
        self._target: str | None = None
        self.avg: float | None = None
        self._history: collections.deque = collections.deque()  # (t, rtt|None)
        self._fails = 0
        self._hop: TraceHop | None = None  # 폴백 대상
        self._traced = False  # 대상당 한 번만 추적한다
        self._tracing = False  # 추적 스레드가 도는 중인지
        # 추적을 상대 선정 즉시 시작하므로, 결과가 '핑이 막혔다'는 판정보다
        # 먼저 도착할 수 있다. 받아두기만 하고 쓸지는 따로 정한다.
        self._trace_done = False
        self._trace_result: TraceHop | None = None
        # IP별 추적 결과. set_target()으로 _traced가 리셋돼도 이건 남으므로
        # 같은 상대를 다시 고르더라도 tracert를 두 번 돌리지 않는다.
        # 값이 None인 항목도 '찾아봤지만 없더라'는 결과라 그대로 캐시한다.
        self._trace_cache: collections.OrderedDict[str, TraceHop | None] = (
            collections.OrderedDict()
        )
        self.trace_note: str | None = None  # 메인이 한 번 출력할 안내

    def set_target(self, ip: str | None) -> None:
        with self._lock:
            if ip != self._target:
                self._target = ip
                self.avg = None
                self._history.clear()
                self._fails = 0
                self._hop = None
                self._traced = False
                self._trace_done = False
                self._trace_result = None

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        while not self._stopped.is_set():
            with self._lock:
                target = self._target
                hop = self._hop
                # 상대를 잡자마자 폴백 경로를 찾아 둔다. 예전엔 핑 3회 실패를
                # 기다린 뒤에야 시작해서, ICMP 막힌 상대면 3초(실패 대기) +
                # 15초(tracert)를 합쳐 19초 동안 화면에 지연이 안 떴다(실측).
                # 추적은 별도 스레드라 핑을 막지 않고, 상대가 ICMP에 응답하면
                # trace_last_hop()이 None을 주므로 결과는 그냥 안 쓰인다.
                start_trace = target is not None and not self._traced
            if not target:
                self._stopped.wait(POLL_INTERVAL)
                continue
            if start_trace:
                self._begin_trace(target)  # 락 밖에서 — _begin_trace가 다시 잡는다

            started = time.monotonic()
            # 목적지가 막혀 있으면 폴백 홉을 대신 잰다.
            probe = hop.ip if hop else target
            rtt = ping_once(probe, self._stopped)

            with self._lock:
                # 대상이 바뀌었으면 방금 결과는 버린다.
                if self._target == target:
                    self._history.append((time.monotonic(), rtt))
                    if rtt is None:
                        self._fails += 1
                    else:
                        self._fails = 0
                        if self.avg is None:
                            self.avg = rtt
                        else:
                            self.avg += (rtt - self.avg) * PING_ALPHA
                    # 이제 막 무응답 문턱을 넘었다면 받아둔 결과를 쓴다.
                    self._use_trace_if_needed()

            remain = PING_INTERVAL - (time.monotonic() - started)
            if remain > 0:
                self._stopped.wait(remain)

    def _begin_trace(self, target: str) -> None:
        """폴백 홉을 찾는다. 캐시에 있으면 즉시, 없으면 별도 스레드에서.

        예전엔 여기서 곧장 trace_last_hop()을 불렀는데, 그러면 tracert가 도는
        내내(막힌 경로에서 24초) 이 루프가 멈춰 핑을 한 발도 못 쐈다. 상대가
        바뀌어도 알아채지 못했다. 추적은 떼어내고 핑은 계속 돌게 둔다.
        """
        with self._lock:
            if target in self._trace_cache:
                # 이미 찾아본 IP다. tracert를 다시 돌릴 이유가 없다.
                self._traced = True
                self._record_trace(target, self._trace_cache[target])
                return
            if self._tracing:
                return  # 다른 추적이 도는 중 — 다음 사이클에 다시 시도한다
            self._tracing = True
            self._traced = True
        threading.Thread(
            target=self._trace_worker, args=(target,), daemon=True, name="Tracer"
        ).start()

    def _trace_worker(self, target: str) -> None:
        found = None
        try:
            found = trace_last_hop(target, self._stopped)
        finally:
            with self._lock:
                self._tracing = False
                # 종료 중에 끊긴 결과는 캐시하지 않는다. '홉 없음'으로 굳으면
                # 다음 세션에서 멀쩡한 경로도 포기해버린다.
                if not self._stopped.is_set():
                    self._trace_cache[target] = found
                    while len(self._trace_cache) > TRACE_CACHE_SIZE:
                        self._trace_cache.popitem(last=False)
                self._record_trace(target, found)

    def _record_trace(self, target: str, found: TraceHop | None) -> None:
        """추적 결과를 보관한다. 반드시 락을 쥔 채로 부른다.

        여기서 곧장 쓰지 않는 이유: 상대를 잡자마자 추적을 시작하므로
        결과가 '핑이 막혔다'는 판정보다 먼저 올 수 있다. 그때 바로
        적용하면 ICMP에 멀쩡히 응답하는 상대까지 홉 RTT(하한)로 바꿔
        표시하게 된다. 쓸지 말지는 _use_trace_if_needed()가 정한다.
        """
        if self._target != target:
            return  # 추적하는 사이에 상대가 바뀌었다
        self._trace_done = True
        self._trace_result = found
        self._use_trace_if_needed()

    def _use_trace_if_needed(self) -> None:
        """보관해 둔 추적 결과를 쓸 때가 됐는지 본다. 락을 쥔 채로 부른다.

        핑이 오고 있으면 폴백은 필요 없다. 무응답이 FAILS_BEFORE_TRACE번
        연속됐을 때만 홉으로 갈아탄다 — 안내 문구도 그때 나간다.
        """
        if not self._trace_done or self._hop is not None:
            return
        if self._fails < self.FAILS_BEFORE_TRACE:
            return  # 아직 핑이 살아 있다. 결과는 그대로 들고 있는다
        target = self._target
        found = self._trace_result
        self._trace_done = False  # 안내는 대상당 한 번만
        if found is None:
            self.trace_note = f"{target}: ICMP 차단 ― 경로상 응답하는 홉도 없음"
        elif found.weak:
            # 경로가 일찍 끊긴 추정치는 실제와 무관할 수 있다.
            # 숫자를 만들어 보여주느니 안 쓰는 편이 낫다.
            self.trace_note = (
                f"{target}: ICMP 차단 ― 경로가 {found.hop}홉에서 끊겨"
                f"(이후 {found.dark_after}홉 무응답) 추정 불가"
            )
        else:
            self._hop = found
            self.avg = None
            self._history.clear()
            # 홉 한도로 끊긴 추적이면 목적지가 얼마나 더 남았는지 모른다.
            # 값은 여전히 하한이지만 그 사실을 숨기지 않는다.
            limit = f", {TRACE_MAX_HOPS}홉까지만 추적" if found.truncated else ""
            self.trace_note = (
                f"{target}: ICMP 차단 ― {found.ip}({found.hop}홉)까지"
                f" 재서 하한으로 표시합니다{limit}"
            )

    def take_note(self) -> str | None:
        """한 번만 출력할 안내를 꺼낸다."""
        with self._lock:
            note, self.trace_note = self.trace_note, None
            return note

    def snapshot(self) -> dict:
        now = time.monotonic()
        with self._lock:
            while self._history and self._history[0][0] < now - PING_HISTORY:
                self._history.popleft()
            got = [r for _, r in self._history if r is not None]
            sent = len(self._history)
            return {
                "avg": self.avg,
                "lo": min(got) if got else None,
                "hi": max(got) if got else None,
                "loss": 100.0 * (sent - len(got)) / sent if sent else 0.0,
                "samples": sent,
                # 폴백을 타는 중이면 값은 '하한'이다. 정확한 RTT가 아니다.
                "hop": self._hop,
            }


# ------------------------- RTSS 오버레이 ------------------------
class OSD:
    """RTSS의 OSD 슬롯에 텍스트를 밀어넣는다.

    RTSS는 DLL export가 아니라 'RTSSSharedMemoryV2' 공유 메모리로 서드파티
    텍스트를 받는다 (SDK/Include/RTSSSharedMemory.h). 구조체가 오프셋과
    크기를 스스로 알려주므로 필드 위치를 하드코딩하지 않는다.

    RTSS가 없거나 안 떠 있으면 조용히 no-op이 된다. 오버레이 때문에 본체가
    죽으면 안 된다.
    """

    MAP_NAME = "RTSSSharedMemoryV2"
    OWNER = "sc6-ping"
    SIGNATURE = 0x52545353  # 'RTSS'
    DEAD = 0xDEAD
    FILE_MAP_ALL_ACCESS = 0x000F001F

    # 헤더 앞부분은 v2 내내 고정이다.
    OFF_SIGNATURE = 0
    OFF_VERSION = 4
    OFF_OSD_ENTRY_SIZE = 20
    OFF_OSD_ARR_OFFSET = 24
    OFF_OSD_ARR_SIZE = 28
    OFF_OSD_FRAME = 32
    OFF_BUSY = 36
    # OSD 엔트리 안에서의 위치
    ENTRY_TEXT = 0  # szOSD[256]
    ENTRY_OWNER = 256  # szOSDOwner[256]
    FIELD = 256
    NUL = bytes(1)

    def __init__(self):
        self._base = None
        self._handle = None
        self._slot = None
        self.reason = "미연결"
        if not IS_WINDOWS:
            self.reason = "Windows 아님"
            return
        self._attach()

    def _attach(self) -> None:
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # OpenFileMapping은 '열기 전용'이다. mmap()으로 열면 RTSS가 꺼져
        # 있을 때 같은 이름의 빈 매핑을 새로 만들어버려서, 아무 데도 안
        # 닿는 곳에 계속 쓰게 된다.
        k32.OpenFileMappingW.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        k32.OpenFileMappingW.restype = wintypes.HANDLE
        k32.MapViewOfFile.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_size_t,
        ]
        k32.MapViewOfFile.restype = ctypes.c_void_p
        k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._k32 = k32

        handle = k32.OpenFileMappingW(self.FILE_MAP_ALL_ACCESS, False, self.MAP_NAME)
        if not handle:
            self.reason = "RTSS 미실행 (트레이에 떠 있어야 함)"
            return
        base = k32.MapViewOfFile(handle, self.FILE_MAP_ALL_ACCESS, 0, 0, 0)
        if not base:
            k32.CloseHandle(handle)
            self.reason = "공유 메모리 매핑 실패"
            return

        self._handle, self._base = handle, base
        sig = self._dw(self.OFF_SIGNATURE)
        if sig == self.DEAD:
            self.reason = "RTSS 종료 중"
            self._detach()
            return
        if sig != self.SIGNATURE:
            self.reason = f"시그니처 불일치 (0x{sig:08X})"
            self._detach()
            return
        ver = self._dw(self.OFF_VERSION)
        if ver < 0x00020000:
            self.reason = f"공유 메모리 v{ver >> 16}.{ver & 0xFFFF} ― v2 필요"
            self._detach()
            return
        self.reason = f"연결됨 (공유 메모리 v{ver >> 16}.{ver & 0xFFFF})"

    def _detach(self) -> None:
        if self._base:
            self._k32.UnmapViewOfFile(ctypes.c_void_p(self._base))
        if self._handle:
            self._k32.CloseHandle(self._handle)
        self._base = self._handle = None

    def _dw(self, off: int) -> int:
        return ctypes.c_uint32.from_address(self._base + off).value

    def _set_dw(self, off: int, val: int) -> None:
        ctypes.c_uint32.from_address(self._base + off).value = val

    def _find_slot(self) -> int | None:
        """내 슬롯을 찾거나 빈 슬롯을 하나 잡는다."""
        arr_off = self._dw(self.OFF_OSD_ARR_OFFSET)
        entry_size = self._dw(self.OFF_OSD_ENTRY_SIZE)
        count = self._dw(self.OFF_OSD_ARR_SIZE)
        if not entry_size or not count:
            return None
        mine = self.OWNER.encode("ascii")
        free = None
        for i in range(count):
            owner_addr = self._base + arr_off + i * entry_size + self.ENTRY_OWNER
            owner = ctypes.string_at(owner_addr, self.FIELD).split(self.NUL, 1)[0]
            if owner == mine:
                return i
            if not owner and free is None:
                free = i
        return free

    @property
    def available(self) -> bool:
        return self._base is not None

    def show(self, text: str) -> None:
        if not self._base:
            return
        try:
            if self._slot is None:
                self._slot = self._find_slot()
                if self._slot is None:
                    self.reason = "빈 OSD 슬롯 없음"
                    self._detach()
                    return

            arr_off = self._dw(self.OFF_OSD_ARR_OFFSET)
            entry_size = self._dw(self.OFF_OSD_ENTRY_SIZE)
            entry = self._base + arr_off + self._slot * entry_size

            payload = text.encode("ascii", errors="replace")[: self.FIELD - 1]
            owner = self.OWNER.encode("ascii")[: self.FIELD - 1]

            # dwBusy 비트 0을 세우고 쓴다. 반드시 다시 내려야 한다 —
            # 안 내리면 모든 클라이언트의 OSD 갱신이 잠긴다.
            self._set_dw(self.OFF_BUSY, 1)
            try:
                ctypes.memset(entry + self.ENTRY_TEXT, 0, self.FIELD)
                ctypes.memmove(entry + self.ENTRY_TEXT, payload, len(payload))
                ctypes.memset(entry + self.ENTRY_OWNER, 0, self.FIELD)
                ctypes.memmove(entry + self.ENTRY_OWNER, owner, len(owner))
                # 프레임 ID를 올려야 서버가 OSD를 다시 그린다.
                self._set_dw(self.OFF_OSD_FRAME, self._dw(self.OFF_OSD_FRAME) + 1)
            finally:
                self._set_dw(self.OFF_BUSY, 0)
        except Exception as e:
            # 한 번 실패하면 조용히 포기한다. 매 프레임 예외를 낼 순 없다.
            self.reason = f"쓰기 실패 ― 비활성화 ({e})"
            self._detach()

    def clear(self) -> None:
        if self._base:
            self.show("")
            self._detach()


# ------------------------- 메인 로직 ---------------------------
def start_sniffer(bpf: str, on_packet) -> AsyncSniffer:
    sniffer = AsyncSniffer(filter=bpf, prn=on_packet, store=False)
    sniffer.start()
    return sniffer


def stop_sniffer(sniffer: AsyncSniffer | None) -> None:
    if sniffer is None:
        return
    try:
        if sniffer.running:
            sniffer.stop()
        else:
            sniffer.join()
    except Exception:
        pass


class ProbeCache:
    """상대 후보 ICMP 프로브 결과를 IP별로 잠시 기억한다.

    pick_opponent()는 표시 루프가 도는 메인 스레드에서 불린다. 캐시가 없으면
    RESELECT_SECONDS마다 같은 후보를 다시 찔러서, ICMP를 막는 후보가 섞이면
    후보 하나당 1초 넘게 화면이 멈춘다. Pinger를 별도 스레드로 뺀 이유가
    바로 그건데 여기서 다시 막으면 의미가 없다.
    """

    def __init__(self, ttl: float = PROBE_CACHE_TTL):
        self.ttl = ttl
        self._seen: dict[str, tuple[float, bool]] = {}

    def responds(self, ip: str) -> bool:
        # 간격 계산은 파일 전반과 맞춰 monotonic을 쓴다 (시계 변경에 안전).
        now = time.monotonic()
        # 매칭 중에는 여러 IP가 스쳐 지나간다. 만료된 항목을 그때그때 버려
        # 세션이 길어져도 딕셔너리가 자라지 않게 한다.
        for old_ip in [k for k, (t, _) in self._seen.items() if now - t >= self.ttl]:
            del self._seen[old_ip]

        hit = self._seen.get(ip)
        if hit is not None:
            return hit[1]
        ok = ping_once(ip) is not None
        self._seen[ip] = (now, ok)
        return ok


def pick_opponent(
    flows: dict[str, Flow], current: str | None, probes: ProbeCache
) -> str | None:
    """트래픽이 많은 순으로 찔러보고 응답하는 IP를 상대로 택한다.

    패킷 수가 가장 많은 IP가 항상 상대인 건 아니다 (스팀 릴레이가 근소하게
    더 많을 때가 있다). 응답이 없는 IP는 어차피 핑을 못 재므로 쓸모가 없다.
    """
    # 이미 고른 상대는 KEEP_RATE까지 떨어져도 유지한다. 대전 중에는 여기서
    # 곧장 빠져나가므로 프로브가 아예 돌지 않는다 — 메인 스레드가 안 막힌다.
    if current is not None:
        held = flows.get(current)
        if held is not None and held.rate >= KEEP_RATE:
            return current

    ranked = sorted(
        (f for f in flows.values() if f.rate >= MIN_RATE),
        key=lambda f: f.count,
        reverse=True,
    )
    if not ranked:
        return None
    for flow in ranked[:PROBE_CANDIDATES]:
        if probes.responds(flow.ip):
            return flow.ip
    return ranked[0].ip  # 아무도 응답 안 하면 트래픽 1위라도 보여준다


def format_osd(ping: dict, flow: Flow | None) -> str:
    """게임 화면용. 지연과 프레임이 주인공이므로 맨 앞에 둔다."""
    parts = []
    if ping["avg"] is not None:
        # 폴백 홉을 재는 중이면 하한이다. '>=' 로 그걸 드러낸다.
        mark = ">=" if ping["hop"] else ""
        parts.append(f"{mark}{ping['avg']:.0f}ms  {mark}{ms_to_frames(ping['avg']):.1f}f")
    else:
        parts.append("ping --")
    if flow and flow.frame_paced:
        parts.append(f"JIT {flow.jitter:.1f}")
        parts.append(f"GAP {flow.gap_rate:.1f}")
    # 손실률은 핑이 응답하는 중일 때만 의미가 있다. 무응답일 때의 100%는
    # 게임 트래픽 손실로 오해되는데, 실제 대전 연결은 멀쩡한 경우가 많다.
    #
    # 폴백 홉을 재는 중에도 숨긴다. 그 손실은 상대가 아니라 경로 중간
    # 라우터가 ICMP를 rate-limit하는 것이다. 실측: 11홉 라우터가 10~33%를
    # 흘리는 동안 대전 연결은 132pkt/s ↑66↓66으로 멀쩡했다. 오버레이에
    # 'LOSS 20%'가 뜨면 게임이 끊기는 걸로 읽을 수밖에 없다.
    if ping["avg"] is not None and ping["loss"] and not ping["hop"]:
        parts.append(f"LOSS {ping['loss']:.0f}%")
    return "SC6  " + "  ".join(parts)


def format_log(stamp: str, ip: str, ping: dict, flow: Flow | None) -> str:
    """콘솔 한 줄.

    폭이 최우선이다. 예전 형식은 전각을 세면 139~150칸이라 120칸 창에서 접히고,
    접힌 줄이 다음 출력과 겹쳐 글자가 섞였다. 판단에 쓰이는 건 평균 지연과 갭이므로
    나머지는 덜어냈다.
    """
    hop = ping["hop"]
    if ping["avg"] is not None:
        mark = ">=" if hop else ""
        head = f"{mark}{ping['avg']:.1f}ms → {ms_to_frames(ping['avg']):.1f}프레임"
        # 최소/최대는 뺐다. 20칸 넘게 먹는데 실제로 보는 건 평균과 갭이다.
        # '하한 N홉'도 뺐다 — '>=' 접두사와 Pinger의 1회성 안내(홉 IP까지 나온다)가
        # 이미 같은 말을 하고 있었다.
    else:
        # 사유(ICMP 차단)도 그 1회성 안내가 설명한다. 매 줄 반복할 이유가 없다.
        head = "핑 무응답"

    tail = ""
    if flow:
        if flow.frame_paced:
            gaps = (
                f"간격 {flow.median_gap:.1f}ms"
                f"  지터 {flow.jitter:.1f}"
                f"  갭 {flow.gap_rate:.1f}/s(최대 {flow.worst_gap:.0f})"
            )
        elif not flow.sampled:
            # 아직 통계를 낼 만큼 안 모였다. 예전엔 여기서도 median_gap(0.0)을
            # 그대로 찍어서 '간격 0.0ms'로 보였다 — 측정값이 0인 것과 구별이 안 됐다.
            gaps = f"간격 --(표본 {flow.gap_samples}/{MIN_GAP_SAMPLES})"
        else:
            # 프레임 페이싱이 아닌 스트림 — 프레임 갭 개념이 성립하지 않는다.
            gaps = f"간격 {flow.median_gap:.1f}ms(비페이싱)"
        # ↑↓도 초당으로 통일한다. 예전엔 앞은 속도, 뒤는 창 누적 개수라
        # 단위가 섞여서 합이 안 맞아 보였다.
        up_rate = flow.up / flow.window
        down_rate = flow.down / flow.window
        tail = (
            f"  {gaps}"
            f"  {flow.rate:.0f}pkt/s ↑{up_rate:.0f}↓{down_rate:.0f}"
        )
    # 무응답일 때의 '손실 100%'는 위 head와 중복이고 오해만 부른다.
    # 폴백 홉을 재는 중이면 그 손실은 중간 라우터의 ICMP rate-limit이지
    # 상대와의 손실이 아니다 — OSD와 같은 이유로 숨긴다.
    loss = (
        f"  손실 {ping['loss']:.0f}%"
        if ping["avg"] is not None and ping["loss"] and not ping["hop"]
        else ""
    )
    return f"{stamp}  {ip:<15s}  {head}{loss}{tail}"


def wait_for_game() -> psutil.Process:
    """게임이 뜰 때까지 기다린다.

    스크립트를 먼저 켜두고 게임을 나중에 실행하는 순서를 위한 것이다.
    오버레이를 쓰는 이상 게임을 띄운 뒤 alt-tab으로 빠져나와 모니터를
    실행하는 건 앞뒤가 안 맞는다.
    """
    announced = False
    while True:
        games = find_processes()[GAME_PROCESS]
        if games:
            return games[0]
        if not announced:
            print(f"[*] {GAME_PROCESS} 대기 중... (Ctrl+C 로 종료)")
            announced = True
        # 프로세스 조회는 1초에 한 번이면 충분하다. sleep은 POLL_INTERVAL로
        # 쪼개서 Ctrl+C 응답성을 유지한다.
        for _ in range(int(1.0 / POLL_INTERVAL)):
            time.sleep(POLL_INTERVAL)


def monitor_session(game: psutil.Process, local_ip: str, pinger: Pinger) -> None:
    """게임이 떠 있는 동안 측정한다. 게임이 꺼지면 반환한다."""
    # RTSS는 매 세션 다시 찾는다. 모니터를 먼저 켜둔 뒤에 RTSS가 떴을 수도 있다.
    osd = OSD()
    print(f"[*] 게임 감지: {GAME_PROCESS} (PID {game.pid})")
    print(f"[*] RTSS 오버레이: {osd.reason}")
    print()

    traffic = TrafficWindow()
    probes = ProbeCache()
    port_set = PortSet()

    def on_packet(pkt):
        if IP not in pkt or UDP not in pkt:
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        outbound = src == local_ip
        remote = dst if outbound else src
        # pkt.time은 Npcap 드라이버 타임스탬프다. 파이썬 콜백 시각을 쓰면
        # 스케줄링 지연이 3ms쯤 섞여 도착 간격 측정이 무의미해진다 (실측).
        if is_valve_relay(remote):
            traffic.add(remote, float(pkt.time), outbound, relay=True)
        elif not is_ignorable(remote, local_ip):
            traffic.add(remote, float(pkt.time), outbound)

    sniffer = None
    current_bpf = None
    opponent = None
    last_reselect = 0.0
    last_log = 0.0
    idle_state = None  # 유휴 로그를 상태 변화 시에만 찍기 위한 것

    try:
        while True:
            now = time.monotonic()

            if not game.is_running():
                print("[*] 게임 종료 ― 대기 상태로 돌아갑니다.")
                return

            # 캡처 스레드에서 난 예외(Npcap 문제 등)를 메인으로 끌어올린다.
            if sniffer is not None and sniffer.exception is not None:
                raise sniffer.exception

            # --- 포트 재열거 / 상대 재선정 (RESELECT_SECONDS 주기) ---
            if now - last_reselect >= RESELECT_SECONDS or sniffer is None:
                last_reselect = now
                owners = find_processes()
                watched = [p for n in NET_OWNER_PROCESSES for p in owners[n]]
                # 스냅샷을 그대로 쓰지 않고 누적한다 — 자세한 이유는 PortSet 참고.
                ports = port_set.update(udp_ports_of(watched))
                bpf = build_filter(ports)
                if bpf != current_bpf:
                    stop_sniffer(sniffer)
                    sniffer = start_sniffer(bpf, on_packet)
                    current_bpf = bpf
                    if bpf == FALLBACK_BPF:
                        label = "폴백(차단 목록)"
                    else:
                        label = f"{len(ports)}개 포트(누적)"
                        # 조용히 자르지 않는다. 버린 게 있으면 상한을 의심할 근거다.
                        if port_set.dropped:
                            label += f", 상한 {port_set.limit} 초과로 {port_set.dropped}개 버림"
                    print(f"[*] 감시 대상 갱신: {label}")

                flows, _ = traffic.snapshot(time.time())
                chosen = pick_opponent(flows, opponent, probes)
                if chosen != opponent:
                    opponent = chosen
                    pinger.set_target(opponent)
                traffic.forget({opponent} if opponent else set())

            # --- 표시 ---
            flows, relay_rate = traffic.snapshot(time.time())
            stats = pinger.snapshot()
            flow = flows.get(opponent) if opponent else None

            # Pinger가 남긴 안내(ICMP 차단 / 폴백 홉)를 한 번만 출력한다.
            note = pinger.take_note()
            if note:
                print(f"[*] {note}")

            if opponent and flow:
                osd.show(format_osd(stats, flow))
                idle_state = None
                if now - last_log >= LOG_INTERVAL:
                    last_log = now
                    print(
                        fit_width(
                            format_log(
                                time.strftime("%H:%M:%S"), opponent, stats, flow
                            )
                        )
                    )
            else:
                # RTSS szOSD는 char 배열이라 ASCII만 그려진다. OSD.show()가
                # encode("ascii", errors="replace")를 하므로 한글을 넣으면
                # 화면에 'SC6  ?? ?'로 뜬다. 오버레이 문구는 영문으로 둔다.
                osd.show("SC6  idle")
                # 유휴 상태에서는 같은 줄을 2초마다 도배하지 않는다.
                # 상태가 바뀔 때만 한 줄 남긴다.
                # MIN_RATE를 여기서도 쓴다 — "릴레이 경유 매치"라는 문구는
                # 대전 수준 속도일 때만 주장해야 맞다. 잡담 수준의 릴레이
                # 트래픽은 매치가 아니므로 '대전 트래픽 없음'이 정확하다.
                state = "relay" if relay_rate >= MIN_RATE else "idle"
                if state != idle_state:
                    idle_state = state
                    stamp = time.strftime("%H:%M:%S")
                    if state == "relay":
                        print(
                            fit_width(
                                f"{stamp}  릴레이 경유 매치 ― 상대 IP 노출 안 됨,"
                                f" 측정 불가 ({relay_rate:.0f}pkt/s)"
                            )
                        )
                    else:
                        print(f"{stamp}  대전 트래픽 없음")

            time.sleep(DISPLAY_INTERVAL)
    finally:
        # 세션이 끝나면 캡처와 핑 대상을 정리한다. Pinger 스레드 자체는
        # 다음 세션에서 재사용하므로 여기서 멈추지 않는다.
        stop_sniffer(sniffer)
        pinger.set_target(None)
        osd.clear()


def run():
    local_ip = get_local_ip()
    print(f"[*] 로컬 IP: {local_ip}")
    print(
        f"[*] 화면 {1 / DISPLAY_INTERVAL:.0f}Hz / 로그 {LOG_INTERVAL:.0f}초"
        "  (Ctrl+C 로 종료)"
    )
    print()

    pinger = Pinger()
    pinger.start()
    try:
        # 게임을 껐다 켜도 계속 물고 간다. 스크립트를 한 번 켜두면 끝.
        while True:
            game = wait_for_game()
            monitor_session(game, local_ip, pinger)
            print()
    finally:
        pinger.stop()


if __name__ == "__main__":
    # run()보다 먼저. 기동 실패 메시지도 안 깨져야 원인을 읽을 수 있다.
    match_console_encoding()
    try:
        run()
    except KeyboardInterrupt:
        print()
        print("종료합니다.")
        sys.exit(0)
    except (PermissionError, RuntimeError, OSError) as e:
        # Npcap 미설치 시 scapy는 PermissionError가 아닌 다른 예외를 던진다.
        print()
        print(f"패킷 캡처를 시작하지 못했습니다: {e}")
        print()
        print("확인할 것:")
        print("  - Npcap이 설치되어 있나요? (https://npcap.com)")
        print('  - Npcap을 "Administrators only"로 설치했다면')
        print("    관리자 권한 터미널에서 다시 실행하세요.")
        sys.exit(1)
