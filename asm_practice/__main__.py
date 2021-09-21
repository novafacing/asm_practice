from argparse import ArgumentParser
from pathlib import Path
from asm_practice.coding.driver import Driver

if __name__ == "__main__":
    parser = ArgumentParser(
        prog="asm_practice",
        description="Interactive ASM programming environment for teaching assembly."
    )
    parser.add_argument(
        "--challenges",
        "-c",
        type=Path,
        required=True,
        help="Path to your challenges.py file defining your challenges. For examples, see `asm-practice/examples/`.",
    )
    parser.add_argument(
        "--flag",
        "-f",
        type=str,
        required=True,
        help="Flag to be used for challenge.",
    )
    args = parser.parse_args()
    driver = Driver(args.challenges, args.flag)
    driver.run()