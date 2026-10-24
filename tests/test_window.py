import os
import unittest
from unittest import mock

from getip import term
from getip.term import WindowFit


class FakeTerminal:
    """Окно, которое слушается CSI 8;строки;колонки t (как Terminal.app) или нет."""

    def __init__(self, columns, lines, obeys=True, screen=(500, 500)):
        self.size = os.terminal_size((columns, lines))
        self.obeys, self.screen, self.written = obeys, screen, []

    def out(self, s):
        self.written.append(s)
        if self.obeys and s.startswith("\033[8;"):
            lines, columns = map(int, s[4:-1].split(";"))
            # больше экрана окно не растёт
            self.size = os.terminal_size((min(columns, self.screen[0]), min(lines, self.screen[1])))

    def requests(self):
        return [s for s in self.written if s.startswith("\033[8;")]


class WindowFitTest(unittest.TestCase):
    def run_with(self, fake):
        patches = [mock.patch.object(term, "TTY", True),
                   mock.patch.object(term, "out", fake.out),
                   mock.patch.object(term, "term_size", lambda: fake.size),
                   mock.patch.object(term.time, "sleep", lambda s: None),
                   mock.patch.object(WindowFit, "WAIT", 0.05)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        w = WindowFit()
        w.enabled = True
        return w

    def test_grows_and_restores(self):
        fake = FakeTerminal(80, 24)
        w = self.run_with(fake)
        self.assertTrue(w.grow(96, 40))
        self.assertEqual(tuple(fake.size), (96, 40))
        w.restore()
        self.assertEqual(tuple(fake.size), (80, 24))

    def test_never_shrinks(self):
        fake = FakeTerminal(150, 60)
        w = self.run_with(fake)
        self.assertFalse(w.grow(96, 40))
        self.assertEqual(fake.requests(), [])
        self.assertTrue(w.grow(96, 70))  # растёт только высота, ширина остаётся 150
        self.assertEqual(tuple(fake.size), (150, 70))

    def test_ignoring_terminal_is_asked_once(self):
        fake = FakeTerminal(80, 24, obeys=False)
        w = self.run_with(fake)
        self.assertFalse(w.grow(96, 40))
        self.assertFalse(w.grow(100, 45))
        self.assertEqual(len(fake.requests()), 1)
        w.restore()
        self.assertEqual(len(fake.requests()), 1)  # возвращать нечего

    def test_screen_limit_is_not_asked_again(self):
        fake = FakeTerminal(80, 24, screen=(200, 35))
        w = self.run_with(fake)
        self.assertTrue(w.grow(96, 40))
        self.assertEqual(tuple(fake.size), (96, 35))
        self.assertFalse(w.grow(96, 40))
        self.assertEqual(len(fake.requests()), 1)

    def test_manual_resize_is_kept(self):
        fake = FakeTerminal(80, 24)
        w = self.run_with(fake)
        w.grow(96, 40)
        fake.size = os.terminal_size((130, 50))  # окно потянули мышкой
        w.restore()
        self.assertEqual(tuple(fake.size), (130, 50))

    def test_disabled(self):
        fake = FakeTerminal(80, 24)
        w = self.run_with(fake)
        w.enabled = False
        self.assertFalse(w.grow(96, 40))
        self.assertEqual(fake.requests(), [])


if __name__ == "__main__":
    unittest.main()
