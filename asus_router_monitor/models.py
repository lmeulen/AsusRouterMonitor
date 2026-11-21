"""Public typed contracts returned by AsusRouterMonitor."""

from typing import Any, TypedDict


class Uptime(TypedDict):
    since: str
    uptime: str


class MemoryUsage(TypedDict):
    mem_total: str
    mem_free: str
    mem_used: str


class CpuUsage(TypedDict, total=False):
    cpu1_total: str
    cpu1_usage: str
    cpu2_total: str
    cpu2_usage: str


class TrafficTotals(TypedDict):
    sent: float
    recv: float


class TrafficRate(TypedDict):
    tx: float
    rx: float


class Traffic(TypedDict):
    speed: TrafficRate
    total: TrafficTotals


class WanStatus(TypedDict, total=False):
    status: str
    statusstr: str
    type: str
    ipaddr: str
    netmask: str
    gateway: str
    dns: str


class ClientInfo(TypedDict, total=False):
    name: str
    nickName: str
    ip: str
    mac: str
    isOnline: str
    isWL: str
    curTx: str
    curRx: str
    totalTx: str
    totalRx: str


class ClientCounts(TypedDict):
    total: int
    wired: int
    wireless: int
    wifi_2_4_ghz: int
    wifi_5_ghz: int
    other_wireless: int
    unknown: int
    radios: dict[str, int]


RouterSettings = dict[str, str]
DhcpLeases = dict[str, Any]
