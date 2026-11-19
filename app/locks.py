"""进程内读写锁。

查询走读锁（可并发），权限变更/版本推进走写锁（独占），
用于验证“并发权限变更 vs 并发查询/缓存失效”的一致性。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager


class RWLock:
    def __init__(self) -> None:
        self._cond = threading.Condition(threading.RLock())
        self._readers = 0
        self._writer = False

    @contextmanager
    def read_lock(self):
        with self._cond:
            while self._writer:
                self._cond.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._cond:
                self._readers -= 1
                if self._readers == 0:
                    self._cond.notify_all()

    @contextmanager
    def write_lock(self):
        with self._cond:
            while self._writer or self._readers > 0:
                self._cond.wait()
            self._writer = True
        try:
            yield
        finally:
            with self._cond:
                self._writer = False
                self._cond.notify_all()


# 全局读写锁：演示规模下单一锁即可保证版本推进与读路径的线性一致
GLOBAL_RW_LOCK = RWLock()
