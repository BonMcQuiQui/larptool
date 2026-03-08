"""
Advanced BitTorrent DHT Crawler

A robust, async DHT node discovery tool using the Kademlia-based
BitTorrent DHT protocol (BEP 5). Supports IPv4/IPv6, configurable
crawl strategies, and structured JSON output.

Usage:
    python dht_crawler.py --max-nodes 200 --max-depth 8 --ping-validate -v
    python dht_crawler.py --get-peers --output results.json
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import ipaddress
import json
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("dht-crawler")


# ---------------------------------------------------------------------------
# Bencode / Bdecode
# ---------------------------------------------------------------------------
MAX_NESTING = 120


def bencode(data: Any) -> bytes:
    """Encode a Python object into bencode format."""
    if isinstance(data, int):
        return b"i" + str(data).encode() + b"e"
    if isinstance(data, (bytes, bytearray)):
        return str(len(data)).encode() + b":" + data
    if isinstance(data, str):
        return bencode(data.encode("utf-8"))
    if isinstance(data, list):
        return b"l" + b"".join(bencode(i) for i in data) + b"e"
    if isinstance(data, dict):
        items = sorted(
            (k.encode("utf-8") if isinstance(k, str) else k, v)
            for k, v in data.items()
        )
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError(f"Unsupported bencode type: {type(data).__name__}")


def bdecode(data: bytes) -> Any:
    """Decode bencoded bytes into a Python object."""

    def _decode(pos: int, depth: int = 0) -> tuple[Any, int]:
        if depth > MAX_NESTING:
            raise ValueError("Max nesting depth exceeded")
        if pos >= len(data):
            raise ValueError("Unexpected EOF")

        ch = data[pos]

        if ch == ord("d"):
            pos += 1
            result: dict[bytes, Any] = {}
            while pos < len(data) and data[pos] != ord("e"):
                key, pos = _decode(pos, depth + 1)
                if not isinstance(key, bytes):
                    raise ValueError("Dict key must be bytes")
                val, pos = _decode(pos, depth + 1)
                result[key] = val
            if pos >= len(data) or data[pos] != ord("e"):
                raise ValueError("Unterminated dictionary")
            return result, pos + 1

        if ch == ord("l"):
            pos += 1
            lst: list[Any] = []
            while pos < len(data) and data[pos] != ord("e"):
                item, pos = _decode(pos, depth + 1)
                lst.append(item)
            if pos >= len(data) or data[pos] != ord("e"):
                raise ValueError("Unterminated list")
            return lst, pos + 1

        if ch == ord("i"):
            pos += 1
            end = data.find(b"e", pos)
            if end == -1:
                raise ValueError("Unterminated integer")
            raw = data[pos:end]
            if (
                not raw
                or raw == b"-0"
                or (raw.startswith(b"0") and len(raw) > 1)
                or (raw.startswith(b"-0") and len(raw) > 2)
            ):
                raise ValueError(f"Non-canonical integer: {raw!r}")
            return int(raw), end + 1

        if chr(ch).isdigit():
            colon = data.find(b":", pos)
            if colon == -1:
                raise ValueError("Missing colon in byte string")
            len_field = data[pos:colon]
            # Reject non-digit bytes, leading zeros (except bare "0"),
            # and absurdly large lengths before they reach int().
            if not len_field or not all(chr(b).isdigit() for b in len_field):
                raise ValueError(f"Invalid byte-string length field: {len_field!r}")
            if len(len_field) > 1 and len_field[0:1] == b"0":
                raise ValueError(f"Leading zero in byte-string length: {len_field!r}")
            if len(len_field) > 10:
                raise ValueError(f"Byte-string length too large: {len_field!r}")
            length = int(len_field)
            start = colon + 1
            if start + length > len(data):
                raise ValueError(
                    f"Byte string at pos {pos} claims {length} bytes, "
                    f"but only {len(data) - start} remain"
                )
            return data[start : start + length], start + length

        raise ValueError(f"Unknown bencode type at pos {pos}: 0x{ch:02x}")

    result, end = _decode(0)
    if end != len(data):
        raise ValueError(f"Trailing data: {len(data) - end} extra bytes")
    return result


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
class AddrFamily(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class DHTNode:
    """A node in the DHT network."""
    node_id: bytes          # 20-byte ID
    ip: str
    port: int
    family: AddrFamily

    @property
    def id_hex(self) -> str:
        return self.node_id.hex()

    @property
    def addr(self) -> tuple[str, int]:
        return (self.ip, self.port)


@dataclass(frozen=True, slots=True)
class Peer:
    """A content-sharing peer returned by get_peers."""
    ip: str
    port: int
    family: AddrFamily


@dataclass
class CrawlStats:
    """Accumulated crawl statistics."""
    queries_sent: int = 0
    responses_received: int = 0
    errors: int = 0
    timeouts: int = 0
    depth_reached: int = 0
    start_time: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def queries_per_sec(self) -> float:
        return self.queries_sent / max(self.elapsed, 0.001)


# ---------------------------------------------------------------------------
# Compact-format parsers
# ---------------------------------------------------------------------------
COMPACT_NODE4_SIZE = 26   # 20 (id) + 4 (ip) + 2 (port)
COMPACT_NODE6_SIZE = 38   # 20 (id) + 16 (ip) + 2 (port)
COMPACT_PEER4_SIZE = 6    # 4 (ip) + 2 (port)
COMPACT_PEER6_SIZE = 18   # 16 (ip) + 2 (port)


def parse_compact_nodes4(data: bytes) -> list[DHTNode]:
    """Parse IPv4 compact node info (BEP 5).

    Malformed individual records are silently skipped rather than
    aborting the entire parse, since responses from the wild frequently
    contain trailing garbage or corrupted entries.
    """
    nodes = []
    count = len(data) // COMPACT_NODE4_SIZE
    for i in range(count):
        off = i * COMPACT_NODE4_SIZE
        chunk = data[off : off + COMPACT_NODE4_SIZE]
        if len(chunk) < COMPACT_NODE4_SIZE:
            break
        try:
            nid = chunk[:20]
            ip = str(ipaddress.IPv4Address(chunk[20:24]))
            port = struct.unpack("!H", chunk[24:26])[0]
        except (ValueError, struct.error) as exc:
            log.debug("Skipping malformed compact-v4 record at offset %d: %s", off, exc)
            continue
        if port > 0:
            nodes.append(DHTNode(nid, ip, port, AddrFamily.IPV4))
    return nodes


def parse_compact_nodes6(data: bytes) -> list[DHTNode]:
    """Parse IPv6 compact node info (BEP 32)."""
    nodes = []
    count = len(data) // COMPACT_NODE6_SIZE
    for i in range(count):
        off = i * COMPACT_NODE6_SIZE
        chunk = data[off : off + COMPACT_NODE6_SIZE]
        if len(chunk) < COMPACT_NODE6_SIZE:
            break
        try:
            nid = chunk[:20]
            ip = str(ipaddress.IPv6Address(chunk[20:36]))
            port = struct.unpack("!H", chunk[36:38])[0]
        except (ValueError, struct.error) as exc:
            log.debug("Skipping malformed compact-v6 record at offset %d: %s", off, exc)
            continue
        if port > 0:
            nodes.append(DHTNode(nid, ip, port, AddrFamily.IPV6))
    return nodes


def parse_compact_peers4(data: bytes | list[bytes]) -> list[Peer]:
    """Parse IPv4 compact peer info from values list or concatenated bytes."""
    peers = []
    if isinstance(data, list):
        for chunk in data:
            if len(chunk) != COMPACT_PEER4_SIZE:
                continue
            try:
                ip = str(ipaddress.IPv4Address(chunk[:4]))
                port = struct.unpack("!H", chunk[4:6])[0]
            except (ValueError, struct.error):
                continue
            if port > 0:
                peers.append(Peer(ip, port, AddrFamily.IPV4))
    else:
        for i in range(len(data) // COMPACT_PEER4_SIZE):
            off = i * COMPACT_PEER4_SIZE
            chunk = data[off : off + COMPACT_PEER4_SIZE]
            try:
                ip = str(ipaddress.IPv4Address(chunk[:4]))
                port = struct.unpack("!H", chunk[4:6])[0]
            except (ValueError, struct.error):
                continue
            if port > 0:
                peers.append(Peer(ip, port, AddrFamily.IPV4))
    return peers


def parse_compact_peers6(data: bytes | list[bytes]) -> list[Peer]:
    """Parse IPv6 compact peer info."""
    peers = []
    if isinstance(data, list):
        for chunk in data:
            if len(chunk) != COMPACT_PEER6_SIZE:
                continue
            try:
                ip = str(ipaddress.IPv6Address(chunk[:16]))
                port = struct.unpack("!H", chunk[16:18])[0]
            except (ValueError, struct.error):
                continue
            if port > 0:
                peers.append(Peer(ip, port, AddrFamily.IPV6))
    else:
        for i in range(len(data) // COMPACT_PEER6_SIZE):
            off = i * COMPACT_PEER6_SIZE
            chunk = data[off : off + COMPACT_PEER6_SIZE]
            try:
                ip = str(ipaddress.IPv6Address(chunk[:16]))
                port = struct.unpack("!H", chunk[16:18])[0]
            except (ValueError, struct.error):
                continue
            if port > 0:
                peers.append(Peer(ip, port, AddrFamily.IPV6))
    return peers


# ---------------------------------------------------------------------------
# Transaction ID manager
# ---------------------------------------------------------------------------
class TransactionManager:
    """
    Maps outstanding transaction IDs → asyncio Futures so responses
    can be routed back to the correct caller without eating other
    callers' packets.
    """

    def __init__(self) -> None:
        self._pending: dict[bytes, asyncio.Future] = {}
        self._counter = random.randint(0, 0xFFFF)

    def allocate(self, loop: asyncio.AbstractEventLoop) -> tuple[bytes, asyncio.Future]:
        self._counter = (self._counter + 1) & 0xFFFF
        tid = struct.pack("!H", self._counter)
        # Collision: cancel the older one
        if tid in self._pending and not self._pending[tid].done():
            self._pending[tid].cancel()
        fut: asyncio.Future = loop.create_future()
        self._pending[tid] = fut
        return tid, fut

    def resolve(self, tid: bytes, response: dict) -> bool:
        fut = self._pending.pop(tid, None)
        if fut and not fut.done():
            fut.set_result(response)
            return True
        return False

    def expire(self, tid: bytes) -> None:
        fut = self._pending.pop(tid, None)
        if fut and not fut.done():
            fut.set_result(None)

    def cancel_all(self) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()


# ---------------------------------------------------------------------------
# Async UDP transport
# ---------------------------------------------------------------------------
class DHTProtocol(asyncio.DatagramProtocol):
    """
    Async UDP protocol that demultiplexes incoming KRPC responses
    by transaction ID rather than by source address, avoiding the
    original bug where one recvfrom loop eats packets meant for
    other outstanding queries.
    """

    def __init__(self, txn_mgr: TransactionManager, stats: CrawlStats) -> None:
        self.txn = txn_mgr
        self.stats = stats
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 10:
            return
        try:
            msg = bdecode(data)
        except (ValueError, IndexError):
            self.stats.errors += 1
            return

        tid = msg.get(b"t")
        if not tid:
            return

        if msg.get(b"y") == b"e":
            # Error response — resolve as None so caller sees failure
            self.txn.resolve(tid, None)  # type: ignore[arg-type]
            self.stats.errors += 1
            return

        self.txn.resolve(tid, msg)
        self.stats.responses_received += 1

    def error_received(self, exc: Exception) -> None:
        log.debug("UDP error: %s", exc)
        self.stats.errors += 1


# ---------------------------------------------------------------------------
# KRPC Client (async)
# ---------------------------------------------------------------------------
class KRPCClient:
    """Async KRPC query client with proper transaction demuxing."""

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        txn_mgr: TransactionManager,
        stats: CrawlStats,
        timeout: float = 4.0,
        retries: int = 1,
    ) -> None:
        self.transport = transport
        self.txn = txn_mgr
        self.stats = stats
        self.timeout = timeout
        self.retries = retries
        self._loop = asyncio.get_running_loop()

    async def query(
        self, addr: tuple[str, int], method: bytes, args: dict
    ) -> dict | None:
        """Send a KRPC query and await the response (or None on timeout)."""
        for attempt in range(1, self.retries + 1):
            tid, fut = self.txn.allocate(self._loop)
            msg = {b"t": tid, b"y": b"q", b"q": method, b"a": args}
            try:
                self.transport.sendto(bencode(msg), addr)
            except (OSError, AttributeError) as exc:
                log.debug("Send failed to %s: %s", addr, exc)
                self.txn.expire(tid)
                self.stats.errors += 1
                continue

            self.stats.queries_sent += 1

            try:
                result = await asyncio.wait_for(fut, timeout=self.timeout)
                if result is not None:
                    return result
            except asyncio.TimeoutError:
                self.txn.expire(tid)
                self.stats.timeouts += 1
                log.debug("Timeout querying %s (attempt %d)", addr, attempt)
            except asyncio.CancelledError:
                self.txn.expire(tid)
                raise

        return None


# ---------------------------------------------------------------------------
# Crawl configuration
# ---------------------------------------------------------------------------
@dataclass
class CrawlConfig:
    max_nodes: int = 200
    max_depth: int = 8
    ping_validate: bool = False
    get_peers: bool = False
    get_peers_sample: int = 30
    concurrency: int = 24
    query_timeout: float = 4.0
    query_retries: int = 1
    inter_query_delay: float = 0.02     # 50 qps ceiling by default
    output_path: Path = Path("dht_crawl_results.json")
    verbose: bool = False

    # Well-known bootstrap nodes
    BOOTSTRAPS: list[tuple[str, int, AddrFamily]] = field(default_factory=lambda: [
        ("router.bittorrent.com", 6881, AddrFamily.IPV4),
        ("dht.transmissionbt.com", 6881, AddrFamily.IPV4),
        ("router.utorrent.com", 6881, AddrFamily.IPV4),
        ("dht.libtorrent.org", 25401, AddrFamily.IPV4),
    ])

    # Public-domain torrents for optional get_peers testing
    TEST_INFOHASHES: list[bytes] = field(default_factory=lambda: [
        # Big Buck Bunny — well-known public domain torrent
        bytes.fromhex("dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c"),
        # Sintel — Blender Foundation, public domain
        bytes.fromhex("08ada5a7a6183aae1e09d831df6748d566095a10"),
    ])


# ---------------------------------------------------------------------------
# Core Crawler
# ---------------------------------------------------------------------------
class DHTCrawler:
    """
    Async BFS crawler over the BitTorrent DHT.

    Key design decisions:
    - Async I/O with transaction-ID demuxing (no packet stealing between queries)
    - Dual-stack: separate IPv4 and IPv6 transports with graceful v6 fallback
    - Bounded concurrency via semaphore with configurable rate limiting
    - Nodes keyed by (ip, port, family) to avoid cross-family collisions
    - Per-result depth tracking for correct BFS semantics in mixed-depth batches
    - Hostile-input-tolerant compact parsers (malformed records skipped, not fatal)
    """

    def __init__(self, config: CrawlConfig) -> None:
        self.cfg = config
        self.my_id = bytes(random.getrandbits(8) for _ in range(20))
        # Keyed by (ip, port, family) so an IPv4 and IPv6 address on
        # the same port are tracked as distinct nodes.
        self.discovered: dict[tuple[str, int, AddrFamily], DHTNode] = {}
        self.peers: set[Peer] = set()
        self.stats = CrawlStats()
        self._sem = asyncio.Semaphore(config.concurrency)

    # -- Target generation --------------------------------------------------

    def _diverse_target(self, depth: int) -> bytes:
        """
        Generate a find_node target that differs from our ID in a
        specific bit position, cycling through all 160 bits across
        successive depths for maximum routing-table coverage.
        """
        bit = depth % 160
        target = bytearray(self.my_id)
        target[bit // 8] ^= 1 << (7 - bit % 8)
        return bytes(target)

    # -- Node extraction ----------------------------------------------------

    @staticmethod
    def _extract_nodes(resp: dict) -> list[DHTNode]:
        """Extract nodes from a KRPC response body."""
        body = resp.get(b"r", {})
        nodes: list[DHTNode] = []
        if b"nodes" in body:
            nodes.extend(parse_compact_nodes4(body[b"nodes"]))
        if b"nodes6" in body:
            nodes.extend(parse_compact_nodes6(body[b"nodes6"]))
        return nodes

    # -- Phases -------------------------------------------------------------

    async def _query_node(
        self,
        client: KRPCClient,
        addr: tuple[str, int],
        target: bytes,
        depth: int,
    ) -> tuple[int, list[DHTNode]]:
        """Send find_node to a single address, return (parent_depth, new nodes)."""
        async with self._sem:
            await asyncio.sleep(self.cfg.inter_query_delay)
            args: dict[bytes, Any] = {
                b"id": self.my_id,
                b"target": target,
            }
            # Request both address families
            args[b"want"] = [b"n4", b"n6"]
            resp = await client.query(addr, b"find_node", args)

        if resp is None:
            return depth, []

        new_nodes = self._extract_nodes(resp)
        added = []
        for node in new_nodes:
            key = (node.ip, node.port, node.family)
            if key not in self.discovered:
                self.discovered[key] = node
                added.append(node)

        if self.cfg.verbose and added:
            log.info(
                "depth=%d  %s:%d → +%d nodes  (total %d)",
                depth, addr[0], addr[1], len(added), len(self.discovered),
            )
        return depth, added

    async def _ping(self, client: KRPCClient, node: DHTNode) -> bool:
        """Verify a node is alive with a ping query."""
        async with self._sem:
            await asyncio.sleep(self.cfg.inter_query_delay)
            resp = await client.query(
                node.addr, b"ping", {b"id": self.my_id}
            )
        return resp is not None

    async def _bfs_crawl(self, client: KRPCClient) -> None:
        """BFS traversal of the DHT from bootstrap nodes.

        Each queue entry carries its own depth so that child nodes inherit
        parent_depth + 1 regardless of what else is in the same batch.
        """
        queue: collections.deque[tuple[tuple[str, int], int]] = collections.deque()
        queried: set[tuple[str, int]] = set()

        # Seed from bootstraps
        for host, port, _af in self.cfg.BOOTSTRAPS:
            queue.append(((host, port), 0))

        while queue and len(self.discovered) < self.cfg.max_nodes:
            # Drain up to concurrency items for parallel dispatch
            batch: list[tuple[tuple[str, int], int]] = []
            while queue and len(batch) < self.cfg.concurrency:
                addr, depth = queue.popleft()
                if depth > self.cfg.max_depth:
                    continue
                if addr in queried:
                    continue
                queried.add(addr)
                batch.append((addr, depth))

            if not batch:
                break

            target_for_depth = {
                d: self._diverse_target(d) for d in {d for _, d in batch}
            }

            tasks = [
                self._query_node(client, addr, target_for_depth[depth], depth)
                for addr, depth in batch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            self.stats.depth_reached = max(
                self.stats.depth_reached, max(d for _, d in batch)
            )

            for result in results:
                if isinstance(result, BaseException):
                    log.debug("Query exception: %s", result)
                    continue
                parent_depth, added_nodes = result
                child_depth = parent_depth + 1
                for node in added_nodes:
                    if len(self.discovered) >= self.cfg.max_nodes:
                        break
                    naddr = node.addr
                    if naddr not in queried:
                        queue.append((naddr, child_depth))

    async def _get_peers_phase(self) -> None:
        """Query a sample of discovered nodes for peers on known torrents."""
        sample = list(self.discovered.values())[: self.cfg.get_peers_sample]
        log.info(
            "get_peers phase: querying %d nodes for %d infohashes",
            len(sample), len(self.cfg.TEST_INFOHASHES),
        )

        async def _ask_peer(node: DHTNode, infohash: bytes) -> None:
            client = self._client_for(node)
            if client is None:
                return
            async with self._sem:
                await asyncio.sleep(self.cfg.inter_query_delay)
                resp = await client.query(
                    node.addr,
                    b"get_peers",
                    {b"id": self.my_id, b"info_hash": infohash},
                )
            if resp is None:
                return
            body = resp.get(b"r", {})
            if b"values" in body:
                self.peers.update(parse_compact_peers4(body[b"values"]))

        tasks = [
            _ask_peer(node, ih)
            for ih in self.cfg.TEST_INFOHASHES
            for node in sample
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    # -- Optional ping validation -------------------------------------------

    async def _validate_nodes(self) -> None:
        """Ping-validate all discovered nodes, removing dead ones."""
        log.info("Ping-validating %d nodes...", len(self.discovered))
        nodes = list(self.discovered.values())

        async def _check(node: DHTNode) -> tuple[DHTNode, bool]:
            client = self._client_for(node)
            if client is None:
                return node, False
            alive = await self._ping(client, node)
            return node, alive

        results = await asyncio.gather(
            *[_check(n) for n in nodes], return_exceptions=True
        )
        alive_count = 0
        for r in results:
            if isinstance(r, BaseException):
                continue
            node, alive = r
            if alive:
                alive_count += 1
            else:
                self.discovered.pop((node.ip, node.port, node.family), None)
        log.info("Validation complete: %d/%d alive", alive_count, len(nodes))

    # -- Main entry ---------------------------------------------------------

    async def run(self) -> dict:
        """Execute the full crawl pipeline and return results dict."""
        loop = asyncio.get_running_loop()
        txn4 = TransactionManager()
        txn6 = TransactionManager()

        # Dual-stack: separate transports for IPv4 and IPv6
        transport4, _proto4 = await loop.create_datagram_endpoint(
            lambda: DHTProtocol(txn4, self.stats),
            local_addr=("0.0.0.0", 0),
            family=socket.AF_INET,
        )

        transport6: asyncio.DatagramTransport | None = None
        txn6_live = False
        try:
            transport6, _proto6 = await loop.create_datagram_endpoint(
                lambda: DHTProtocol(txn6, self.stats),
                local_addr=("::", 0),
                family=socket.AF_INET6,
            )
            txn6_live = True
        except OSError:
            log.warning("IPv6 socket unavailable — crawling IPv4 only")

        try:
            client4 = KRPCClient(
                transport4, txn4, self.stats,
                timeout=self.cfg.query_timeout,
                retries=self.cfg.query_retries,
            )
            client6 = (
                KRPCClient(
                    transport6, txn6, self.stats,
                    timeout=self.cfg.query_timeout,
                    retries=self.cfg.query_retries,
                )
                if transport6 is not None
                else None
            )
            self._clients = {AddrFamily.IPV4: client4, AddrFamily.IPV6: client6}
            # Default to IPv4 for bootstrap (hostnames resolve to v4)
            self._default_client = client4

            # Phase 1: BFS crawl
            log.info("Starting BFS crawl (max_nodes=%d, max_depth=%d, dual_stack=%s)",
                     self.cfg.max_nodes, self.cfg.max_depth, txn6_live)
            await self._bfs_crawl(self._default_client)
            log.info("BFS complete: %d nodes discovered", len(self.discovered))

            # Phase 1.5: Optional ping validation
            if self.cfg.ping_validate and self.discovered:
                await self._validate_nodes()

            # Phase 2: Optional get_peers
            if self.cfg.get_peers and self.discovered:
                await self._get_peers_phase()
                log.info("get_peers complete: %d peers found", len(self.peers))

        finally:
            txn4.cancel_all()
            txn6.cancel_all()
            transport4.close()
            if transport6 is not None:
                transport6.close()

        return self._build_results()

    def _client_for(self, node: DHTNode) -> KRPCClient | None:
        """Return the appropriate KRPC client for a node's address family."""
        return self._clients.get(node.family)

    # -- Results ------------------------------------------------------------

    def _build_results(self) -> dict:
        nodes = sorted(self.discovered.values(), key=lambda n: n.id_hex)
        unique_ips = {n.ip for n in nodes}

        return {
            "summary": {
                "total_nodes": len(nodes),
                "unique_ips": len(unique_ips),
                "ipv4_nodes": sum(1 for n in nodes if n.family == AddrFamily.IPV4),
                "ipv6_nodes": sum(1 for n in nodes if n.family == AddrFamily.IPV6),
                "peers_collected": len(self.peers),
                "ping_validation": self.cfg.ping_validate,
                "get_peers_enabled": self.cfg.get_peers,
                "depth_reached": self.stats.depth_reached,
                "queries_sent": self.stats.queries_sent,
                "responses_received": self.stats.responses_received,
                "timeouts": self.stats.timeouts,
                "errors": self.stats.errors,
                "elapsed_seconds": round(self.stats.elapsed, 2),
                "queries_per_second": round(self.stats.queries_per_sec, 1),
            },
            "nodes": [
                {
                    "id": n.id_hex[:16] + "…",
                    "ip": n.ip,
                    "port": n.port,
                    "family": n.family.value,
                }
                for n in nodes
            ],
            "peers": [
                {"ip": p.ip, "port": p.port, "family": p.family.value}
                for p in sorted(self.peers, key=lambda p: (p.ip, p.port))
            ],
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Async BitTorrent DHT crawler with structured output",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--max-nodes", type=int, default=200,
                   help="Stop after discovering this many nodes")
    p.add_argument("--max-depth", type=int, default=8,
                   help="Maximum BFS depth")
    p.add_argument("--concurrency", type=int, default=24,
                   help="Max simultaneous in-flight queries")
    p.add_argument("--timeout", type=float, default=4.0,
                   help="Per-query timeout in seconds")
    p.add_argument("--delay", type=float, default=0.02,
                   help="Min delay between outbound queries (rate limit)")
    p.add_argument("--ping-validate", action="store_true",
                   help="Ping-validate discovered nodes after crawl")
    p.add_argument("--get-peers", action="store_true",
                   help="Run get_peers phase on public-domain torrents")
    p.add_argument("--get-peers-sample", type=int, default=30,
                   help="How many nodes to query in get_peers phase")
    p.add_argument("-o", "--output", type=Path, default=Path("dht_crawl_results.json"),
                   help="Output JSON path")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


async def async_main(args: argparse.Namespace) -> None:
    cfg = CrawlConfig(
        max_nodes=args.max_nodes,
        max_depth=args.max_depth,
        concurrency=args.concurrency,
        query_timeout=args.timeout,
        inter_query_delay=args.delay,
        ping_validate=args.ping_validate,
        get_peers=args.get_peers,
        get_peers_sample=args.get_peers_sample,
        output_path=args.output,
        verbose=args.verbose,
    )

    crawler = DHTCrawler(cfg)
    results = await crawler.run()

    cfg.output_path.write_text(json.dumps(results, indent=2))
    print(json.dumps(results["summary"], indent=2))
    print(f"\nFull results → {cfg.output_path}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
