import unittest

import cvss_calculator

class TestCVSS(unittest.TestCase):
    def test_base_score1(self):
        self.assertEqual(cvss_calculator.get_scores("tc1.json")[0], 7.8)
    def test_temporal_score1(self):
        self.assertEqual(cvss_calculator.get_scores("tc1.json")[1], 6.4)
    def test_environmental_score1(self):
        self.assertEqual(cvss_calculator.get_scores("tc1.json")[2], 9.2)

    def test_base_score2(self):
        self.assertEqual(cvss_calculator.get_scores("tc2.json")[0], 10.0)
    def test_temporal_score2(self):
        self.assertEqual(cvss_calculator.get_scores("tc2.json")[1], 8.3)
    def test_environmental_score2(self):
        self.assertEqual(cvss_calculator.get_scores("tc2.json")[2], 9.0)

    def test_base_score3(self):
        self.assertEqual(cvss_calculator.get_scores("tc3.json")[0], 6.2)
    def test_temporal_score3(self):
        self.assertEqual(cvss_calculator.get_scores("tc3.json")[1], 4.9)
    def test_environmental_score3(self):
        self.assertEqual(cvss_calculator.get_scores("tc3.json")[2], 7.5)

if __name__ == '__main__':
    unittest.main()
