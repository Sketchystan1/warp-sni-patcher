import unittest

from prepare_release import release_entry, release_plan


class ReleaseTests(unittest.TestCase):
    def plan(self, **overrides):
        args = dict(version="1.2.0", event="push", ref_type="branch", ref_name="master",
                    requested_tag="", prerelease=False, existing_sha=None, head_sha="new")
        args.update(overrides)
        return release_plan(**args)

    def test_notes_include_only_latest_version(self):
        version, notes = release_entry("# Changelog\n\n## [1.2.0] - 2026-10-15\n\n- New GUI\n\n## [1.1.0]\n- Old GUI\n")
        self.assertEqual(version, "1.2.0")
        self.assertEqual(notes, "- New GUI")

    def test_empty_notes_and_missing_version_rejected(self):
        for text in ("# Changelog", "## [1.2.0]\n\n## [1.1.0]\n- Old"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                release_entry(text)

    def test_new_version_releases(self):
        plan = self.plan()
        self.assertEqual(plan["should_release"], "true")
        self.assertEqual(plan["tag"], "v1.2.0")
        self.assertEqual(plan["is_prerelease"], "false")

    def test_existing_version_skips_branch_push(self):
        self.assertEqual(self.plan(existing_sha="old")["should_release"], "false")

    def test_tag_push_and_manual_rerun_use_same_commit(self):
        tagged = self.plan(ref_type="tag", ref_name="v1.2.0", existing_sha="new")
        manual = self.plan(event="workflow_dispatch", existing_sha="new")
        self.assertEqual(tagged["should_release"], "true")
        self.assertEqual(manual["should_release"], "true")

    def test_other_commit_cannot_replace_release(self):
        with self.assertRaises(ValueError):
            self.plan(event="workflow_dispatch", existing_sha="old")
        with self.assertRaises(ValueError):
            self.plan(ref_type="tag", ref_name="v1.2.0", existing_sha="old")

    def test_mismatched_or_injected_tags_rejected(self):
        for tag in ("v1.1.0", "v1.2.0\nshould_release=true", "v1.2.0; echo bad"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.plan(event="workflow_dispatch", requested_tag=tag)

    def test_prerelease_version_and_explicit_flag(self):
        version, _ = release_entry("## [1.2.0-rc.1]\n- Candidate\n")
        self.assertEqual(self.plan(version=version)["is_prerelease"], "true")
        self.assertEqual(self.plan(prerelease=True)["is_prerelease"], "true")


if __name__ == "__main__":
    unittest.main()
