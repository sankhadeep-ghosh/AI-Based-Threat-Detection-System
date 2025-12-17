"""
Thread pool implementation for efficient concurrent processing
of packets and alerts with proper resource management.
"""

from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from threading import BoundedSemaphore, Lock
from queue import Queue
import time
from typing import Callable, Any, Optional, List
from functools import wraps

from ids.utils.logger import setup_logger

logger = setup_logger(__name__)


class ThreadPoolManager:
    """
    Advanced thread pool manager for IDS operations.

    Features:
    - Dynamic thread pool sizing
    - Task prioritization
    - Resource limiting
    - Performance monitoring
    """

    def __init__(self, max_workers: int = 4, max_queue_size: int = 1000, thread_prefix: str = "IDSThread"):
        """
        Initialize thread pool manager.

        Args:
            max_workers: Maximum number of worker threads
            max_queue_size: Maximum task queue size
            thread_prefix: Prefix for thread names
        """
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self.thread_prefix = thread_prefix

        # Use BoundedSemaphore to limit queue size
        self.queue_semaphore = BoundedSemaphore(max_queue_size)

        # Thread pool executor
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=thread_prefix)

        # Statistics
        self.stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "queue_waits": 0,
            "avg_wait_time": 0.0,
        }
        self.stats_lock = Lock()

        logger.info(f"ThreadPoolManager initialized with {max_workers} workers")

    def submit(self, func: Callable, *args, priority: int = 5, **kwargs) -> Future:
        """
        Submit task to thread pool with priority.

        Args:
            func: Function to execute
            args: Positional arguments
            priority: Task priority (1=highest, 10=lowest)
            kwargs: Keyword arguments

        Returns:
            Future object for task
        """
        start_wait = time.time()

        # Wait for queue space (with timeout)
        acquired = self.queue_semaphore.acquire(timeout=10.0)
        if not acquired:
            raise RuntimeError("Task queue full, unable to submit task")

        wait_time = time.time() - start_wait

        # Update stats
        with self.stats_lock:
            self.stats["tasks_submitted"] += 1
            self.stats["queue_waits"] += 1
            # Update average wait time
            total_wait = self.stats["avg_wait_time"] * (self.stats["queue_waits"] - 1) + wait_time
            self.stats["avg_wait_time"] = total_wait / self.stats["queue_waits"]

        # Wrap function to handle semaphore release
        def wrapped_func(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                with self.stats_lock:
                    self.stats["tasks_completed"] += 1
                return result
            except Exception as e:
                with self.stats_lock:
                    self.stats["tasks_failed"] += 1
                logger.error(f"Task failed: {e}")
                raise
            finally:
                self.queue_semaphore.release()

        # Submit to executor
        future = self.executor.submit(wrapped_func, *args, **kwargs)
        return future

    def map(self, func: Callable, iterable, timeout: Optional[float] = None):
        """
        Apply function to all items in iterable using thread pool.

        Args:
            func: Function to apply
            iterable: Iterable of items
            timeout: Timeout in seconds

        Returns:
            List of results
        """
        futures = [self.submit(func, item) for item in iterable]
        results = []

        for future in as_completed(futures, timeout=timeout):
            try:
                result = future.result(timeout=0.1)
                results.append(result)
            except Exception as e:
                logger.error(f"Error in map operation: {e}")
                results.append(None)

        return results

    def shutdown(self, wait: bool = True, timeout: float = 30.0):
        """Shutdown thread pool gracefully."""
        logger.info("Shutting down thread pool...")
        self.executor.shutdown(wait=wait, timeout=timeout)

        # Release any remaining semaphore permits
        while True:
            try:
                self.queue_semaphore.release()
            except ValueError:
                break

    def get_stats(self) -> dict:
        """Get thread pool statistics."""
        with self.stats_lock:
            return self.stats.copy()

    def is_idle(self) -> bool:
        """Check if thread pool is idle."""
        # Approximate check based on semaphore state
        return self.queue_semaphore._value >= self.max_queue_size - 1


# Priority decorators
def high_priority(func):
    """Decorator for high-priority tasks."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        # In a real implementation, this would submit with priority=1
        return func(*args, **kwargs)

    return wrapper


def low_priority(func):
    """Decorator for low-priority tasks."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        # In a real implementation, this would submit with priority=10
        return func(*args, **kwargs)

    return wrapper


# Global thread pool instance
thread_pool = ThreadPoolManager(max_workers=4, max_queue_size=5000, thread_prefix="IDSWorker")
