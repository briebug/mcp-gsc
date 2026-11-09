"""
Tests for the coverage gaps found in the Briebug review of 2026-11-09:
credential selection, filters reaching the API, the sitemap router's write gate,
and write-tool error handling. All Google calls are mocked.
Run with: pytest test_gaps.py -v
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from googleapiclient.errors import HttpError

READONLY = ["https://www.googleapis.com/auth/webmasters.readonly"]
SITE = "sc-domain:example.com"
SITEMAP = "https://example.com/sitemap.xml"


def _load(env: dict | None = None):
    base = {"GSC_SKIP_OAUTH": "true", "GSC_USE_ADC": "false", "GSC_DATA_STATE": "all", "GSC_ALLOW_DESTRUCTIVE": "false"}
    with patch.dict(os.environ, {**base, **(env or {})}, clear=False):
        sys.modules.pop("gsc_server", None)
        import gsc_server as mod
    return mod


def _http_error(status: int, reason: str = "", message: str = "msg") -> HttpError:
    body = {"error": {"message": message, "errors": [{"reason": reason}]}}
    return HttpError(resp=MagicMock(status=status), content=json.dumps(body).encode())


# --- Credential selection ------------------------------------------------------------------

class TestServiceAccountKeyFile(unittest.TestCase):

    def test_key_file_loaded_with_readonly_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "key.json")
            open(key, "w").write("{}")
            mod = _load({"GSC_CREDENTIALS_PATH": key})
            creds = MagicMock()
            with patch("gsc_server.service_account.Credentials.from_service_account_file",
                       return_value=creds) as load, \
                 patch("gsc_server.build", return_value="svc") as build:
                self.assertEqual(mod.get_gsc_service(), "svc")
            load.assert_called_once_with(key, scopes=READONLY)
            self.assertIs(build.call_args.kwargs["credentials"], creds)

    def test_broken_key_file_is_named_in_the_error(self):
        """A key that fails to load must not vanish silently: the error names it and why."""
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "key.json")
            open(key, "w").write("not json")
            mod = _load({"GSC_CREDENTIALS_PATH": key})
            with patch("gsc_server.service_account.Credentials.from_service_account_file",
                       side_effect=ValueError("bad key format")):
                with self.assertRaises(FileNotFoundError) as ctx:
                    mod.get_gsc_service()
            self.assertIn(key, str(ctx.exception))
            self.assertIn("bad key format", str(ctx.exception))


class TestOAuthPaths(unittest.TestCase):

    def _mod(self, tmp):
        return _load({"GSC_SKIP_OAUTH": "false", "GSC_CONFIG_DIR": tmp})

    def test_first_sign_in_runs_flow_with_readonly_scope_and_saves_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            mod = self._mod(tmp)
            token, secrets = os.path.join(tmp, "token.json"), os.path.join(tmp, "secrets.json")
            open(secrets, "w").write("{}")
            creds = MagicMock()
            creds.to_json.return_value = '{"token": "new"}'
            with patch.object(mod, "TOKEN_FILE", token), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets), \
                 patch("gsc_server.InstalledAppFlow") as flow_cls, \
                 patch("gsc_server.build", return_value="svc"):
                flow_cls.from_client_secrets_file.return_value.run_local_server.return_value = creds
                self.assertEqual(mod.get_gsc_service_oauth(), "svc")
            flow_cls.from_client_secrets_file.assert_called_once_with(secrets, READONLY)
            flow_cls.from_client_secrets_file.return_value.run_local_server.assert_called_once_with(port=0)
            self.assertEqual(open(token).read(), '{"token": "new"}')
            self.assertEqual(stat.S_IMODE(os.stat(token).st_mode), 0o600)

    def test_corrupt_token_file_falls_through_to_sign_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            mod = self._mod(tmp)
            token = os.path.join(tmp, "token.json")
            open(token, "w").write("not json")
            with patch.object(mod, "TOKEN_FILE", token), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmp, "missing.json")):
                with self.assertRaises(FileNotFoundError):
                    mod.get_gsc_service_oauth()
            self.assertEqual(open(token).read(), "not json", "a corrupt token must be kept for inspection")

    def test_failed_refresh_keeps_the_token_file(self):
        """Regression guard for upstream issue #56: a failed refresh must not delete the token."""
        with tempfile.TemporaryDirectory() as tmp:
            mod = self._mod(tmp)
            token = os.path.join(tmp, "token.json")
            open(token, "w").write('{"old": "token"}')
            creds = MagicMock(valid=False, expired=True, refresh_token="r")
            creds.refresh.side_effect = Exception("invalid_grant")
            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=creds), \
                 patch.object(mod, "TOKEN_FILE", token), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmp, "missing.json")):
                with self.assertRaises(FileNotFoundError):
                    mod.get_gsc_service_oauth()
            self.assertEqual(open(token).read(), '{"old": "token"}')


# --- Filters must reach the Search Analytics request -----------------------------------------

class TestAdvancedFilters(unittest.IsolatedAsyncioTestCase):

    def _service(self, rows=None):
        service = MagicMock()
        service.searchanalytics().query().execute.return_value = {"rows": rows or []}
        service.searchanalytics().query.reset_mock()
        return service

    def _body(self, service):
        return service.searchanalytics().query.call_args.kwargs["body"]

    async def test_single_filter_reaches_the_request(self):
        mod, service = _load(), self._service([{"keys": ["seo"], "clicks": 1}])
        with patch("gsc_server.get_gsc_service", return_value=service):
            await mod.get_advanced_search_analytics(
                SITE, filter_dimension="country", filter_operator="equals", filter_expression="usa")
        self.assertEqual(self._body(service)["dimensionFilterGroups"],
                         [{"filters": [{"dimension": "country", "operator": "equals", "expression": "usa"}]}])

    async def test_multiple_filters_reach_the_request(self):
        filters = [{"dimension": "country", "operator": "equals", "expression": "usa"},
                   {"dimension": "device", "operator": "equals", "expression": "MOBILE"}]
        mod, service = _load(), self._service([{"keys": ["seo"], "clicks": 1}])
        with patch("gsc_server.get_gsc_service", return_value=service):
            await mod.get_advanced_search_analytics(SITE, filters=json.dumps(filters))
        self.assertEqual(self._body(service)["dimensionFilterGroups"], [{"filters": filters}])

    async def test_no_filter_sends_no_filter_group(self):
        mod, service = _load(), self._service([{"keys": ["seo"], "clicks": 1}])
        with patch("gsc_server.get_gsc_service", return_value=service):
            await mod.get_advanced_search_analytics(SITE)
        self.assertNotIn("dimensionFilterGroups", self._body(service))

    async def test_malformed_filters_are_refused_before_any_api_call(self):
        mod = _load()
        for bad in ('[{"dimension": "country", "operator": "equals"}]', "[]", '{"dimension": "x"}'):
            service = self._service()
            with self.subTest(filters=bad), patch("gsc_server.get_gsc_service", return_value=service):
                result = await mod.get_advanced_search_analytics(SITE, filters=bad)
                self.assertIn("filter", result.lower())
                service.searchanalytics().query.assert_not_called()

    async def test_no_data_message_lists_the_filters_applied(self):
        mod, service = _load(), self._service([])
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                SITE, filter_dimension="page", filter_operator="contains", filter_expression="/blog/")
        self.assertIn("page contains '/blog/'", result)


# --- The sitemap router must honour the write switch --------------------------------------

class TestManageSitemapsRouter(unittest.IsolatedAsyncioTestCase):

    async def test_submit_and_delete_via_router_are_blocked_by_default(self):
        mod, service = _load({"GSC_ALLOW_DESTRUCTIVE": "false"}), MagicMock()
        with patch("gsc_server.get_gsc_service", return_value=service):
            for action in ("submit", "delete"):
                with self.subTest(action=action):
                    result = await mod.manage_sitemaps(SITE, action, sitemap_url=SITEMAP)
                    self.assertIn("GSC_ALLOW_DESTRUCTIVE", result)
        service.sitemaps().submit.assert_not_called()
        service.sitemaps().delete.assert_not_called()

    async def test_list_routes_to_the_listing(self):
        mod, service = _load(), MagicMock()
        service.sitemaps().list().execute.return_value = {"sitemap": [{"path": SITEMAP}]}
        with patch("gsc_server.get_gsc_service", return_value=service):
            data = json.loads(await mod.manage_sitemaps(SITE, "list"))
        self.assertEqual(data["sitemaps"][0]["path"], SITEMAP)

    async def test_invalid_action_and_missing_url_are_refused(self):
        mod, service = _load(), MagicMock()
        with patch("gsc_server.get_gsc_service", return_value=service):
            self.assertIn("Invalid action", await mod.manage_sitemaps(SITE, "purge"))
            self.assertIn("requires a sitemap_url", await mod.manage_sitemaps(SITE, "details"))
        service.sitemaps().get.assert_not_called()


# --- Write-tool error handling -------------------------------------------------------------

class TestWriteToolErrors(unittest.IsolatedAsyncioTestCase):

    async def test_add_site_maps_google_errors(self):
        mod = _load({"GSC_ALLOW_DESTRUCTIVE": "true"})
        cases = [(_http_error(409), "already added"),
                 (_http_error(403, "forbidden"), "verify ownership"),
                 (_http_error(400, "invalidParameter"), "Invalid site URL"),
                 (_http_error(503), "currently down")]
        for error, expected in cases:
            service = MagicMock()
            service.sites().add().execute.side_effect = error
            with self.subTest(status=error.resp.status), patch("gsc_server.get_gsc_service", return_value=service):
                self.assertIn(expected, await mod.add_site("https://example.com/"))

    async def test_delete_site_maps_google_errors(self):
        mod = _load({"GSC_ALLOW_DESTRUCTIVE": "true"})
        cases = [(_http_error(404), "was not found"),
                 (_http_error(403, "forbidden"), "don't have permission"),
                 (_http_error(429), "Too many requests")]
        for error, expected in cases:
            service = MagicMock()
            service.sites().delete().execute.side_effect = error
            with self.subTest(status=error.resp.status), patch("gsc_server.get_gsc_service", return_value=service):
                self.assertIn(expected, await mod.delete_site("https://example.com/"))


if __name__ == "__main__":
    unittest.main()
