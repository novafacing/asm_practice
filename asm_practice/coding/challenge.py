from dataclasses import dataclass
from typing import Callable, List, Optional

from qiling import Qiling


@dataclass
class ArchSpec:
    pwntools_arch: str
    pwntools_os: str
    qiling_rootfs: str
    qiling_ostype: str
    qiling_archtype: str


@dataclass
class TestCase:
    preconditions: List[Callable[[Qiling], None]]
    postconditions: List[Callable[[Qiling], bool]]


@dataclass
class Challenge:
    archspec: ArchSpec
    instructions: str
    testcases: List[TestCase]
    secret: str
    pseudocode: Optional[str] = None
