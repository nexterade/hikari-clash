"""Penegak aturan version bump semantik (lihat CLAUDE.md): VERSION valid dan selaras dengan CHANGELOG.md."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
HEADING = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class Versioning(unittest.TestCase):
    def test_version_file_is_valid_semver(self):
        raw = read("VERSION")
        self.assertEqual(raw.strip(), raw.strip().lstrip("vV"), "VERSION tanpa awalan 'v'")
        self.assertRegex(raw.strip(), SEMVER)
        self.assertEqual(len(raw.strip().splitlines()), 1, "VERSION hanya satu baris")

    def test_changelog_top_entry_matches_version(self):
        versions = HEADING.findall(read("CHANGELOG.md"))
        self.assertTrue(versions, "CHANGELOG.md tidak punya entri '## [X.Y.Z]'")
        self.assertEqual(versions[0], read("VERSION").strip(),
                         "entri teratas CHANGELOG.md harus sama dengan VERSION (lupa bump atau lupa catat?)")

    def test_changelog_versions_are_unique_and_descending(self):
        versions = HEADING.findall(read("CHANGELOG.md"))
        tup = [tuple(int(x) for x in v.split(".")) for v in versions]
        self.assertEqual(len(set(tup)), len(tup), "nomor versi dobel di CHANGELOG.md")
        self.assertEqual(tup, sorted(tup, reverse=True), "CHANGELOG.md harus urut dari versi terbaru ke terlama")

    def test_changelog_entry_has_date_and_content(self):
        text = read("CHANGELOG.md")
        top = HEADING.search(text)
        body = text[top.end():].split("\n## [", 1)[0]
        if top.group(1) != "0.4.0":                      # 0.4.0 = versi dasar tanpa catatan rinci
            self.assertRegex(text[top.start():top.end() + 14], r"\] - \d{4}-\d{2}-\d{2}")
            self.assertRegex(body, r"### (Ditambahkan|Diubah|Diperbaiki|Dihapus)")

    def test_rule_file_is_present_and_names_the_sources_of_truth(self):
        rule = read("CLAUDE.md")
        for needle in ("VERSION", "CHANGELOG.md", "MINOR", "PATCH", "MAJOR", "tests/test_version.py"):
            self.assertIn(needle, rule)


if __name__ == "__main__":
    unittest.main()
