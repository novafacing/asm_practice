class Helpers:
    @classmethod
    def get_multiline_input(cls) -> str:
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
