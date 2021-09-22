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
    """
    Main loop and initialization for challenge driver.

    Runs each stage and runs user provided asm, checks it, and gives flags.
    """

    def __init__(self, challenge_file: Path, flag: str, secrets: bool = False) -> None:
        """
        Initialize the asm practice driver.

        :param challenge_file: The path to a python file that defines an iterable of
            Challenge objects, with each representing a "level" in the game.
        :param flag: The flag to present the player with at the end.
        :param secrets: Whether or not to enable checkpoint secrets that
            allow the user to jump to the last level they completed if they
            need to reconnect.
        """
        assert challenge_file.exists()
        spec = spec_from_file_location("module.name", str(challenge_file.resolve()))
        self.challenges = module_from_spec(spec)
        spec.loader.exec_module(self.challenges)
        self.challenges = self.challenges.challenges
        self.flag = flag
        self.secrets = secrets

    def run(self) -> None:
        """
        Run the game.

        For each level, get code from the user, run it, and check each assertion
        on the output state of the system.
        """

        if self.secrets:
            secret = input(
                "Enter a level password or press enter if you don't have one:\n>>> "
            ).strip()

            if secret == "":
                pass
            elif secret not in (*map(lambda c: c.secret, self.challenges),):
                print("Invalid password.")
            else:
                self.challenges = self.challenges[
                    next(i for i, c in enumerate(self.challenges) if c.secret == secret)
                    + 1 :
                ]

        for i, challenge in enumerate(self.challenges):
            while True:
                context(
                    arch=challenge.archspec.pwntools_arch,
                    os=challenge.archspec.pwntools_os,
                )

                print(Helpers.header(i))

                print(Helpers.reflow(challenge.instructions))

                if challenge.pseudocode is not None:
                    print(Helpers.pseudocode(challenge.pseudocode))

                code = Helpers.get_multiline_input()

                try:
                    asm_code = asm(code)
                except PwnlibException:
                    print("Code could not be assembled. Please try again.")
                    continue

                ql = Qiling(
                    shellcoder=asm_code,
                    rootfs=challenge.archspec.qiling_rootfs,
                    ostype=challenge.archspec.qiling_ostype,
                    archtype=challenge.archspec.qiling_archtype,
                )

                state = ql.save(mem=True, reg=True, fd=True)

                for testcase in challenge.testcases:
                    for codecondition, msg in testcase.codeconditions:
                        if not codecondition(code):
                            print(f"Failed! Reason: {msg}")
                            exit(1)

                    ql.restore(state)

                    for precondition in testcase.preconditions:
                        precondition(ql)

                    ql.run()

                    for postcondition, msg in testcase.postconditions:
                        if not postcondition(ql):
                            print(f"Failed! Reason: {msg}")
                            exit(1)

                print(f"Success! Level password is: {challenge.secret}\n")
                break

        print(f"You have completed all levels! Here's the flag: {self.flag}")
