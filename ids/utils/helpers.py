"""
Performance optimization utilities - provides helper functions
for improving system performance and resource usage.
"""

import time
import functools
from typing import Callable, Any, Dict
from threading import Lock


class RateLimiter:
    """
    Thread-safe rate limiter using token bucket algorithm.

    Usage:
        limiter = RateLimiter(rate=100, burst=200)  # 100/sec, burst 200
        if limiter.acquire():
            # Process request
    """

    def __init__(self, rate: float, burst: int = None):
        """
        Initialize rate limiter.

        Args:
            rate: Sustained rate (operations per second)
            burst: Maximum burst size (default: 2 * rate)
        """
        self.rate = rate
        self.burst = burst or int(rate * 2)
        self.tokens = float(self.burst)
        self.last_update = time.time()
        self.lock = Lock()

    def acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens acquired, False otherwise
        """
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update

            # Add tokens based on elapsed time
            self.tokens += elapsed * self.rate
            self.tokens = min(self.tokens, self.burst)
            self.last_update = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_wait_time(self, tokens: int = 1) -> float:
        """Get estimated wait time for tokens."""
        with self.lock:
            if self.tokens >= tokens:
                return 0.0

            needed = tokens - self.tokens
            return needed / self.rate


def timed_cache(seconds: int = 60, maxsize: int = 128):
    """
    Decorator for function result caching with TTL.

    Args:
        seconds: Cache TTL in seconds
        maxsize: Maximum number of cached results
    """

    def decorator(func: Callable) -> Callable:
        cache = {}
        cache_timestamps = {}
        lock = Lock()

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            now = time.time()

            with lock:
                # Check if cached and not expired
                if key in cache:
                    if now - cache_timestamps[key] < seconds:
                        return cache[key]
                    else:
                        # Remove expired entry
                        del cache[key]
                        del cache_timestamps[key]

                # Compute and cache
                result = func(*args, **kwargs)

                # Manage cache size
                if len(cache) >= maxsize:
                    # Remove oldest entry
                    oldest_key = min(cache_timestamps, key=cache_timestamps.get)
                    del cache[oldest_key]
                    del cache_timestamps[oldest_key]

                cache[key] = result
                cache_timestamps[key] = now

                return result

        # Add cache management methods
        wrapper.clear_cache = lambda: (cache.clear(), cache_timestamps.clear())
        wrapper.cache_info = lambda: {"size": len(cache), "maxsize": maxsize, "ttl": seconds}

        return wrapper

    return decorator


class PerformanceMonitor:
    """
    Performance monitoring utility for tracking execution times.

    Usage:
        monitor = PerformanceMonitor()
        with monitor.measure("packet_processing"):
            process_packet(packet)
        print(monitor.get_stats())
    """

    def __init__(self):
        self.measurements: Dict[str, list] = {}
        self.lock = Lock()

    def measure(self, name: str):
        """Context manager for measuring execution time."""
        return self.MeasurementContext(self, name)

    class MeasurementContext:
        def __init__(self, monitor, name: str):
            self.monitor = monitor
            self.name = name
            self.start_time = None

        def __enter__(self):
            self.start_time = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            elapsed = time.time() - self.start_time
            self.monitor._record(self.name, elapsed)

    def _record(self, name: str, elapsed: float) -> None:
        """Record a measurement."""
        with self.lock:
            if name not in self.measurements:
                self.measurements[name] = []
            self.measurements[name].append(elapsed)

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        stats = {}
        with self.lock:
            for name, times in self.measurements.items():
                if times:
                    stats[name] = {
                        "count": len(times),
                        "avg": sum(times) / len(times),
                        "min": min(times),
                        "max": max(times),
                        "total": sum(times),
                    }
        return stats

    def reset(self) -> None:
        """Reset all measurements."""
        with self.lock:
            self.measurements.clear()


def batch_process(items: list, batch_size: int, process_func: Callable) -> None:
    """
    Process items in batches to improve memory efficiency.

    Args:
        items: List of items to process
        batch_size: Size of each batch
        process_func: Function to process each batch
    """
    for i in range(0, len(items), batch_size):
        batch = items[i : i + batch_size]
        process_func(batch)


def optimize_scapy_filter(bpf_filter: str) -> str:
    """
    Optimize BPF filter for better performance.

    Args:
        bpf_filter: Original BPF filter string

    Returns:
        Optimized filter string
    """
    # Remove redundant parentheses
    bpf_filter = bpf_filter.strip()
    while bpf_filter.startswith("(") and bpf_filter.endswith(")"):
        bpf_filter = bpf_filter[1:-1].strip()

    # Simplify common patterns
    replacements = {"tcp and (tcp)": "tcp", "udp and (udp)": "udp", "ip and (ip)": "ip", "  ": " "}

    for old, new in replacements.items():
        bpf_filter = bpf_filter.replace(old, new)

    return bpf_filter.strip()


# Global performance monitor instance
performance_monitor = PerformanceMonitor()
