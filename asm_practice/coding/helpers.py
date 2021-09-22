"""Helper functions for asm_practice module."""

from textwrap import dedent, wrap

from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import CLexer


class Helpers:
    """Class of simple helper functions for the asm_practice module."""

    WIDTH: int = 80

    @classmethod
    def get_multiline_input(cls) -> str:
        """
        Get a multiline string of input from the player.
        """
        PROMPT = ">>> "
        contents = ""
        while True:
            try:
                line = input(PROMPT)
            except EOFError:
                break
            else:
                contents += line
                if line.strip() == "":
                    break
                PROMPT = "--> "
        return contents

    @classmethod
    def reflow(cls, text: str) -> str:
        """
        Reflow text into lines of specified width.

        :param text: The text to reflow.
        """
        return "\n".join(wrap(cls.dedent(text), width=cls.WIDTH))

    @classmethod
    def dedent(cls, text: str) -> str:
        """
        Dedent a code block.

        :param text: The text to dedent.
        """
        return dedent(text)

    @classmethod
    def header(cls, level: int) -> str:
        """
        Generate a correctly formatted level header.

        :param level: The numbered level the player is on.
        """

        levelname = f"LEVEL 0x{level:03x}"
        surround_width = ((cls.WIDTH - 2) - len(levelname)) // 2
        return f"{'=' * surround_width} {levelname} {'=' * surround_width}".ljust(
            cls.WIDTH, "="
        )

    @classmethod
    def pseudocode(cls, code: str) -> str:
        """
        Format pseudocode for display to the user.

        Highlights, dedents, and adds line numbers to a piece of code.

        :param code: The raw code to output."""
        pcode = "\n"
        pcode += "=" * cls.WIDTH + "\n"
        pcode += (
            "\n".join(
                highlight(
                    cls.dedent(code), CLexer(), TerminalFormatter(linenos=True)
                ).splitlines()[:-1]
            )
            + "\n"
        )
        pcode += "=" * cls.WIDTH + "\n"
        return pcode
