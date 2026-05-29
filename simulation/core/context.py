"""Thread-safe simulation context.

SimContext holds all mutable shared state across generators.  The
``compromised`` set is protected by a ``threading.RLock`` — callers MUST
use the provided accessor methods and never touch the set directly.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from core.models import Attacker, Host, User


@dataclass
class SimContext:
    """Shared mutable simulation state, thread-safe via RLock."""

    hosts: list[Host]
    users: list[User]
    attacker: Attacker
    compromised: set[str] = field(default_factory=set)
    _lock: threading.RLock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize the reentrant lock after dataclass fields are set."""
        self._lock = threading.RLock()

    def add_compromised(self, host: str) -> None:
        """Mark *host* as compromised (thread-safe)."""
        with self._lock:
            self.compromised.add(host)

    def is_compromised(self, host: str) -> bool:
        """Check whether *host* has been compromised (thread-safe)."""
        with self._lock:
            return host in self.compromised

    def get_host(self, name: str) -> Host | None:
        """Look up a host by name."""
        for h in self.hosts:
            if h.name == name:
                return h
        return None

    def get_user(self, username: str) -> User | None:
        """Look up a user by username."""
        for u in self.users:
            if u.username == username:
                return u
        return None
