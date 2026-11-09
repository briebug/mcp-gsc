"""
Optional live test against the real Search Console API.

Mocked tests cannot catch a change in the shape of Google's responses (upstream
once read rich-result issues from a key the API never returns). This test can.

Skipped unless GSC_LIVE_SITE is set, for example:
    GSC_USE_ADC=true GSC_LIVE_SITE=sc-domain:briebug.com uv run --with pytest pytest -q test_live.py
It only reads. CI does not set GSC_LIVE_SITE, so CI skips it.
"""
import asyncio
import json
import os
import unittest

SITE = os.environ.get("GSC_LIVE_SITE")


@unittest.skipUnless(SITE, "set GSC_LIVE_SITE (and real credentials) to run the live test")
class TestLiveSearchConsole(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("GSC_ALLOW_DESTRUCTIVE", "false")
        import gsc_server
        cls.mod = gsc_server

    def run_tool(self, coro):
        return asyncio.run(coro)

    def test_site_is_listed(self):
        data = json.loads(self.run_tool(self.mod.list_properties()))
        self.assertIn(SITE, [p["site_url"] for p in data["properties"]])

    def test_search_analytics_rows_have_the_expected_shape(self):
        data = json.loads(self.run_tool(self.mod.get_search_analytics(SITE, days=28, dimensions="page", row_limit=5)))
        self.assertGreater(data["row_count"], 0)
        for row in data["rows"]:
            self.assertEqual(set(row), {"page", "clicks", "impressions", "ctr", "position"})

    def test_a_page_filter_really_narrows_the_results(self):
        top = json.loads(self.run_tool(self.mod.get_search_analytics(SITE, days=28, dimensions="page", row_limit=1)))
        page = top["rows"][0]["page"]
        data = json.loads(self.run_tool(self.mod.get_advanced_search_analytics(
            SITE, dimensions="page", filter_dimension="page", filter_operator="equals",
            filter_expression=page, row_limit=50)))
        self.assertEqual({row["page"] for row in data["rows"]}, {page})


if __name__ == "__main__":
    unittest.main()
