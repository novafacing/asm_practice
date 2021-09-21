"""CLI driver for asm_practice module."""

from argparse import ArgumentParser
from pathlib import Path

from asm_practice.coding.driver import Driver

if __name__ == "__main__":
    parser = ArgumentParser(
        prog="asm_practice",
        description="Interactive ASM programming environment for teaching assembly.",
    )
    parser.add_argument(
        "--challenges",
        "-c",
        type=Path,
        required=True,
        help=(
            "Path to your challenges.py file defining your challenges. "
            "For examples, see `asm-practice/examples/`."
        ),
    )
    parser.add_argument(
        "--flag",
        "-f",
        type=str,
        required=True,
        help="Flag to be used for challenge.",
    )
    parser.add_argument(
        "--secrets",
        "-s",
        action="store_true",
        default=False,
        help="Whether or not to allow using a secret to jump to a saved level.",
    )

    args = parser.parse_args()
    driver = Driver(args.challenges, args.flag, args.secrets)
    driver.run()
