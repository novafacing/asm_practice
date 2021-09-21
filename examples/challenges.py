from qiling import Qiling

from asm_practice.coding.challenge import ArchSpec, Challenge, TestCase

challenges = []

amd64 = ArchSpec(
    pwntools_arch="amd64",
    pwntools_os="linux",
    qiling_rootfs="qiling/examples/rootfs/x86_linux/",
    qiling_ostype="linux",
    qiling_archtype="x8664",
)

challenges.append(
    Challenge(
        archspec=amd64,
        instructions="Set rdi to 0x1337",
        testcases=[
            TestCase(
                preconditions=[lambda ql: setattr(ql.reg, "rdi", 0x0)],
                postconditions=[lambda ql: ql.reg.rdi == 0x1337],
            )
        ],
        secret="code{very_1337}",
    )
)

challenges.append(
    Challenge(
        archspec=amd64,
        instructions="Translate the following pseudocode to asm:",
        pseudocode="""
if (rax == 0x1337) {
    rsi = 0x10;
} else if (rax == 0x1447) {
    rsi = 0x20;
}""",
        testcases=[
            TestCase(
                preconditions=[lambda ql: setattr(ql.reg, "rax", 0x1337)],
                postconditions=[lambda ql: ql.reg.rsi == 0x10],
            ),
            TestCase(
                preconditions=[lambda ql: setattr(ql.reg, "rax", 0x1447)],
                postconditions=[lambda ql: ql.reg.rsi == 0x20],
            ),
        ],
        secret="code{n1c3_control_fl0w}",
    )
)
