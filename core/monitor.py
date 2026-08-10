"""
core/monitor.py
Real-time FiveM resource folder monitor.
Uses watchdog to detect file system changes and triggers re-scans.
"""

import os
import threading
import time
import json
import logging
from typing import Callable, Optional, Set

try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler,
        FileCreatedEvent,
        FileModifiedEvent,
        FileDeletedEvent,
        DirCreatedEvent,
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

log = logging.getLogger("fivem.monitor")


ChangeCallback = Callable[[str, str, str], None]
# Args: (event_type, resource_name, file_path)


class _FiveMEventHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Handles file system events from watchdog."""

    def __init__(self, resources_path: str, callback: ChangeCallback,
                 debounce_seconds: float = 2.0) -> None:
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.resources_path = resources_path
        self.callback = callback
        self.debounce_seconds = debounce_seconds
        self._pending: dict = {}
        self._lock = threading.Lock()

        # Important FiveM files that trigger immediate alerts
        self.critical_files = {
            "fxmanifest.lua", "__resource.lua",
            "server.lua", "client.lua", "shared.lua",
            "config.lua", "main.lua",
        }

    def _get_resource_name(self, path: str) -> str:
        """Extract resource name from a file path."""
        rel = os.path.relpath(path, self.resources_path)
        parts = rel.split(os.sep)
        if len(parts) >= 1:
            return parts[0]
        return "unknown"

    def _debounce_fire(self, key: str, event_type: str,
                       resource_name: str, file_path: str) -> None:
        """Fire callback after debounce delay."""
        time.sleep(self.debounce_seconds)
        with self._lock:
            if key in self._pending:
                del self._pending[key]
        self.callback(event_type, resource_name, file_path)

    def _schedule(self, event_type: str, path: str) -> None:
        resource_name = self._get_resource_name(path)
        key = f"{event_type}:{path}"

        with self._lock:
            if key in self._pending:
                return  # Already pending
            self._pending[key] = True

        t = threading.Thread(
            target=self._debounce_fire,
            args=(key, event_type, resource_name, path),
            daemon=True,
        )
        t.start()

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._schedule("created", event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._schedule("modified", event.src_path)

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self._schedule("deleted", event.src_path)


class FiveMMonitor:
    """
    Real-time monitor for FiveM resources/ directory.
    Watches for file changes and fires callbacks.
    """

    def __init__(self, resources_path: str, change_callback: ChangeCallback,
                 debounce_seconds: float = 2.0) -> None:
        self.resources_path = resources_path
        self.change_callback = change_callback
        self.debounce_seconds = debounce_seconds
        self._observer: Optional[object] = None
        self._running = False

    @property
    def is_available(self) -> bool:
        return WATCHDOG_AVAILABLE

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> bool:
        """Start monitoring. Returns True if started successfully."""
        if not WATCHDOG_AVAILABLE:
            log.warning("watchdog not installed. Real-time monitoring unavailable.")
            return False

        if self._running:
            return True

        if not os.path.isdir(self.resources_path):
            log.error(f"Cannot monitor non-existent directory: {self.resources_path}")
            return False

        try:
            handler = _FiveMEventHandler(
                self.resources_path, self.change_callback, self.debounce_seconds
            )
            self._observer = Observer()
            self._observer.schedule(handler, self.resources_path, recursive=True)
            self._observer.start()
            self._running = True
            log.info(f"Monitoring started: {self.resources_path}")
            return True
        except Exception as e:
            log.error(f"Failed to start monitor: {e}")
            return False

    def stop(self) -> None:
        """Stop monitoring."""
        if self._observer and self._running:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
        self._running = False
        self._observer = None
        log.info("Monitoring stopped.")

    def restart(self, new_path: Optional[str] = None) -> bool:
        """Restart the monitor, optionally with a new path."""
        self.stop()
        if new_path:
            self.resources_path = new_path
        return self.start()
