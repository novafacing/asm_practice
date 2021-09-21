from pwn import asm, context
from pwnlib.exception import PwnlibException
from qiling import Qiling
from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import TerminalFormatter

from asm_practice.coding.helpers import Helpers

from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec


class Driver:
    def __init__(self, challenge_file: Path, flag: str) -> None:
        assert challenge_file.exists()
        spec = spec_from_file_location("module.name", str(challenge_file.resolve()))
        self.challenges = module_from_spec(spec)
        spec.loader.exec_module(self.challenges)
        self.flag = flag

    def run(self) -> None:
        for challenge in self.challenges.challenges:
            while True:
                context(
                    arch=challenge.archspec.pwntools_arch,
                    os=challenge.archspec.pwntools_os,
                )
                print(challenge.instructions)

                if challenge.pseudocode is not None:
                    print(
                        highlight(challenge.pseudocode, CLexer(), TerminalFormatter())
                    )

                code = Helpers.get_multiline_input()

                try:
                    asm_code = asm(code)
                except PwnlibException:
                    print("Assembly code could not be assembled. Please try again.")
                    continue

                ql = Qiling(
                    shellcoder=asm_code,
                    rootfs=challenge.archspec.qiling_rootfs,
                    ostype=challenge.archspec.qiling_ostype,
                    archtype=challenge.archspec.qiling_archtype,
                )

                state = ql.save(mem=True, reg=True, fd=True)

                for testcase in challenge.testcases:
                    ql.restore(state)
                    for precondition in testcase.preconditions:
                        precondition(ql)
                    ql.run()
                    for postcondition in testcase.postconditions:
                        if not postcondition(ql):
                            print("Failed!")
                            exit(1)

                print(f"Success! Level password is: {challenge.secret}")
                break

        print(f"You have completed all levels! Here's the flag: {self.flag}")
