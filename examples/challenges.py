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
        instructions="Set rdi to 0x1337 using only one instruction.",
        # No pseudocode for this one.
        testcases=[
            TestCase(
                # Only use one instruction
                codeconditions=[
                    (lambda c: len(c.splitlines()) == 1, "Too many instructions!"),
                    (lambda c: c.count(";") <= 1, "Too many instructions!"),
                ],
                # Ensure rdi starts 0x00
                preconditions=[lambda ql: setattr(ql.reg, "rdi", 0x0)],
                # Ensure rdi is 0x1337 after code runs
                postconditions=[(lambda ql: ql.reg.rdi == 0x1337, "rdi != 0x1337")],
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
                # No codeconditions
                # Set rax to 0x1337 for the first branch test.
                preconditions=[lambda ql: setattr(ql.reg, "rax", 0x1337)],
                # Make sure rsi is 0x10 for the first branch test.
                postconditions=[
                    (lambda ql: ql.reg.rsi == 0x10, "rsi != 0x10 when rax == 0x1337!")
                ],
            ),
            TestCase(
                # No codeconditions
                # Set rax to 0x1447 for the second branch test.
                preconditions=[lambda ql: setattr(ql.reg, "rax", 0x1447)],
                # Make sure rsi is 0x20 for the second branch test.
                postconditions=[
                    (lambda ql: ql.reg.rsi == 0x20, "rsi != 0x20 when rax == 0x1447!")
                ],
            ),
        ],
        secret="code{n1c3_control_fl0w}",
    )
)
