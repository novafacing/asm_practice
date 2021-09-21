from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from pwn import asm, context
from pwnlib.exception import PwnlibException
from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import CLexer
from qiling import Qiling

from asm_practice.coding.helpers import Helpers


class Driver:
    def __init__(self, challenge_file: Path, flag: str, secrets: bool = False) -> None:
        assert challenge_file.exists()
        spec = spec_from_file_location("module.name", str(challenge_file.resolve()))
        self.challenges = module_from_spec(spec)
        spec.loader.exec_module(self.challenges)
        self.challenges = self.challenges.challenges
        self.flag = flag
        self.secrets = secrets

    def run(self) -> None:
        if self.secrets:
            secret = input("Enter a level password:\n>>> ").strip()
            if secret not in (*map(lambda c: c.secret, self.challenges),):
                print("Invalid password.")
            else:
                self.challenges = self.challenges[
                    next(i for i, c in enumerate(self.challenges) if c.secret == secret)
                    + 1 :
                ]

        for challenge in self.challenges:
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
