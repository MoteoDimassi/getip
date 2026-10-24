import unittest

from getip.widgets import fit_details, screen_rows

TIPS = "\n".join([
    "  Что делает",
    "    Первая строка описания.",
    "    Вторая строка описания.",
    "  Что делать вам",
    "    Шаг первый.",
    "    Шаг второй.",
]) + "\n"


class FitDetailsTest(unittest.TestCase):
    def test_short_text_is_padded(self):
        self.assertEqual(fit_details("  Заголовок\n", 3), ["  Заголовок", "", ""])
        self.assertEqual(fit_details("", 2), ["", ""])

    def test_long_text_is_cut_at_section(self):
        lines = fit_details(TIPS, 5)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[:3], TIPS.split("\n")[:3])  # первый раздел целиком
        self.assertIn("…", lines[3])
        self.assertEqual(lines[4], "")

    def test_cut_inside_first_section(self):
        lines = fit_details(TIPS, 2)
        self.assertEqual(lines[0], "  Что делает")
        self.assertIn("…", lines[1])

    def test_no_room(self):
        self.assertEqual(fit_details(TIPS, 0), [])


class ScreenRowsTest(unittest.TestCase):
    def test_counts_wrapped_lines_and_cursor_row(self):
        self.assertEqual(screen_rows("a\nb\n", 80), 3)           # две строки и строка под курсор
        self.assertEqual(screen_rows("x" * 100 + "\n", 80), 3)   # длинная строка переносится
        self.assertEqual(screen_rows("\033[1mцвет\033[0m", 4), 1)  # цветовые коды места не занимают


if __name__ == "__main__":
    unittest.main()
