"""Thread-safe event bus: the simulation thread publishes, the GUI thread drains."""
from __future__ import annotations

import queue
import threading
from typing import List

from .models import SimEvent


class EventBus:
    """Queue-based bus plus a bounded history of log events (used for export)."""

    def __init__(self, history_limit: int = 5000) -> None:
        self._queue: "queue.Queue[SimEvent]" = queue.Queue()
        self._history: List[SimEvent] = []
        self._lock = threading.Lock()
        self._limit = history_limit

    def publish(self, event: SimEvent) -> None:
        """Called from any thread."""
        self._queue.put(event)
        if event.kind == "log":
            with self._lock:
                self._history.append(event)
                if len(self._history) > self._limit:
                    del self._history[: len(self._history) - self._limit]

    def drain(self, limit: int = 200) -> List[SimEvent]:
        """Called from the GUI thread; returns at most ``limit`` pending events."""
        items: List[SimEvent] = []
        while len(items) < limit:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def history(self) -> List[SimEvent]:
        with self._lock:
            return list(self._history)

    def clear(self) -> None:
        with self._lock:
            self._history.clear()
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
