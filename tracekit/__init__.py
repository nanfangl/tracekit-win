"""TraceKit - 软件行为记录器（外部观测，不注入目标进程）"""
from .core import Bus, Store, NullBus, write_meta, read_meta  # noqa: F401

__version__ = "1.0.0"
