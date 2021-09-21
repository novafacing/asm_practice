from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple

from qiling import Qiling


@dataclass
class ArchSpec:
    """
    Specifies an Architecture to use with pwntools/Qiling
    """

    pwntools_arch: str
    pwntools_os: str
    qiling_rootfs: str
    qiling_ostype: str
    qiling_archtype: str


@dataclass
class TestCase:
    """
    Specifies the pre and post-conditions for a testcase
    """

    codeconditions: Iterable[Tuple[Callable[[str], bool], str]] = ()
    preconditions: Iterable[Callable[[Qiling], None]] = ()
    postconditions: Iterable[Tuple[Callable[[Qiling], bool], str]] = ()


@dataclass
class Challenge:
    """
    Specifies a challenge (this is actually a challenge *stage*)
    """

    archspec: ArchSpec
    testcases: Iterable[TestCase]
    instructions: str
    secret: Optional[str] = None
    pseudocode: Optional[str] = None
