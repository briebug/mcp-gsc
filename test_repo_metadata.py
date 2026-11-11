"""
Repository metadata guards for the briebug fork (review of 2026-11-11).

These tests read files in the checkout, not the server. They fail if the hosted
third-party service ad returns to the README, or if a plugin manifest points
users at the upstream repository or the upstream author's hosted service.
Run with: pytest test_repo_metadata.py -v
"""
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FORK_URL = "https://github.com/briebug/mcp-gsc"
PLUGIN_MANIFESTS = [".claude-plugin/plugin.json", ".cursor-plugin/plugin.json"]
# The hosted MCP service. A user who follows this link sends Search Console
# data (possibly a client's) to a third party that no one here has reviewed.
HOSTED_SERVICE = "advancedgsc.com/mcp"
UPSTREAM_MARKERS = ["AminForou/mcp-gsc", "advancedgsc.com"]


def _read(rel: str) -> str:
    with open(os.path.join(HERE, rel), encoding="utf-8") as f:
        return f.read()


class TestReadmeHasNoHostedServiceAd(unittest.TestCase):
    def test_readme_does_not_link_the_hosted_mcp_service(self):
        readme = _read("README.md")
        self.assertGreater(len(readme), 1000, "README.md is unexpectedly short; the check would prove nothing")
        lines = [n for n, line in enumerate(readme.splitlines(), 1) if HOSTED_SERVICE in line]
        self.assertEqual(lines, [], f"README.md links the hosted service on line(s) {lines}")


class TestPluginManifestsPointAtTheFork(unittest.TestCase):
    def test_repository_and_homepage_are_the_fork(self):
        for rel in PLUGIN_MANIFESTS:
            with self.subTest(manifest=rel):
                manifest = json.loads(_read(rel))
                self.assertEqual(manifest.get("repository"), FORK_URL, rel)
                self.assertEqual(manifest.get("homepage"), FORK_URL, rel)

    def test_no_url_field_points_upstream(self):
        for rel in PLUGIN_MANIFESTS:
            manifest = json.loads(_read(rel))
            for key, value in manifest.items():
                if not isinstance(value, str):
                    continue
                for marker in UPSTREAM_MARKERS:
                    with self.subTest(manifest=rel, key=key, marker=marker):
                        self.assertNotIn(marker, value, f"{rel}: {key}")


class TestSecurityPolicyAndOwners(unittest.TestCase):
    def test_security_policy_directs_reports_to_private_reporting(self):
        policy = _read("SECURITY.md")
        self.assertIn(f"{FORK_URL}/security/advisories/new", policy)
        self.assertIn("Do not open a public issue", policy)

    def test_codeowners_assigns_every_path(self):
        rules = [line.split() for line in _read(".github/CODEOWNERS").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        self.assertIn(["*", "@jessesanders"], rules)


if __name__ == "__main__":
    unittest.main()
