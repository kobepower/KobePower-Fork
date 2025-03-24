import unittest
from kobe import KobeDevice  # Assumes SWIG wrapper

class KobeTest(unittest.TestCase):
    def setUp(self):
        self.device = KobeDevice("/dev/ttyACM0")

    def test_auth(self):
        resp = self.device.challenge_response(b"\x00" * 6)
        self.assertEqual(len(resp), 4)

if __name__ == "__main__":
    unittest.main()