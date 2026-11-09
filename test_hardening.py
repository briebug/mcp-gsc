"""
Hardening tests for the briebug fork (security review of 2026-11-09, controls 1-4).

Most tests assert a hardened behaviour and fail on upstream 0.4.2; a few are
positive controls that pass either way (for example, stdio still starts).
All Google calls are mocked. Run with: pytest test_hardening.py -v
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
READONLY = ["https://www.googleapis.com/auth/webmasters.readonly"]


def _load(env: dict | None = None):
    base = {"GSC_SKIP_OAUTH": "true", "GSC_USE_ADC": "false", "GSC_DATA_STATE": "all", "GSC_ALLOW_DESTRUCTIVE": "false"}
    with patch.dict(os.environ, {**base, **(env or {})}, clear=False):
        sys.modules.pop("gsc_server", None)
        import gsc_server as mod
    return mod


# --- Control 1 (F1): no config may run the latest PyPI release -----------------------

class TestPinnedLaunch(unittest.TestCase):
    CONFIGS = [".mcp.json", "mcp.json"]

    def test_configs_never_launch_the_pypi_package(self):
        for name in self.CONFIGS:
            with open(os.path.join(HERE, name)) as f:
                servers = json.load(f)["mcpServers"]
            self.assertTrue(servers, name)
            for server in servers.values():
                self.assertNotEqual(server["command"], "uvx", f"{name}: uvx installs the newest PyPI release")
                self.assertNotIn("mcp-search-console", server.get("args", []), name)

    def test_configs_run_the_locked_local_source(self):
        for name in self.CONFIGS:
            with open(os.path.join(HERE, name)) as f:
                server = next(iter(json.load(f)["mcpServers"].values()))
            self.assertEqual(server["command"], "uv", name)
            self.assertIn("--frozen", server["args"], f"{name}: must use uv.lock as committed")
            self.assertIn("gsc_server.py", server["args"], name)


# --- Control 2 (F2): stdio only ------------------------------------------------------------

class TestStdioOnly(unittest.TestCase):

    def test_stdio_runs(self):
        mod = _load()
        with patch.dict(os.environ, {"MCP_TRANSPORT": "stdio"}), patch.object(mod.mcp, "run") as run:
            mod.main()
        run.assert_called_once_with(transport="stdio")

    def test_network_transports_are_refused(self):
        mod = _load()
        for transport in ("sse", "http", "streamable-http"):
            with self.subTest(transport=transport), \
                 patch.dict(os.environ, {"MCP_TRANSPORT": transport}), \
                 patch.object(mod.mcp, "run") as run:
                with self.assertRaises(ValueError) as ctx:
                    mod.main()
                self.assertIn("stdio", str(ctx.exception))
                run.assert_not_called()

    def test_dns_rebinding_protection_is_never_disabled(self):
        with open(os.path.join(HERE, "gsc_server.py")) as f:
            self.assertNotIn("enable_dns_rebinding_protection = False", f.read())


# --- Control 3 (F4): keyless Google standard credentials ----------------------------------

class TestApplicationDefaultCredentials(unittest.TestCase):

    def test_adc_used_with_readonly_scope_and_nothing_else(self):
        mod = _load({"GSC_USE_ADC": "true", "GSC_SKIP_OAUTH": "false"})
        creds = MagicMock()
        with patch("gsc_server.google.auth.default", return_value=(creds, "briebug")) as default, \
             patch("gsc_server.get_gsc_service_oauth", side_effect=AssertionError("OAuth must not run")), \
             patch("gsc_server.service_account.Credentials.from_service_account_file",
                   side_effect=AssertionError("key files must not be read")), \
             patch("gsc_server.build", return_value="svc") as build:
            self.assertEqual(mod.get_gsc_service(), "svc")
        default.assert_called_once_with(scopes=READONLY)
        self.assertIs(build.call_args.kwargs["credentials"], creds)

    def test_adc_failure_fails_closed(self):
        import google.auth.exceptions as gae
        mod = _load({"GSC_USE_ADC": "true", "GSC_SKIP_OAUTH": "false"})
        with patch("gsc_server.google.auth.default", side_effect=gae.DefaultCredentialsError("none")), \
             patch("gsc_server.get_gsc_service_oauth", side_effect=AssertionError("no fallback to OAuth")), \
             patch("gsc_server.service_account.Credentials.from_service_account_file",
                   side_effect=AssertionError("no fallback to key files")):
            with self.assertRaises(gae.DefaultCredentialsError):
                mod.get_gsc_service()

    def test_adc_off_by_default(self):
        self.assertFalse(_load().USE_ADC)


# --- Control 3 (F3): token file is owner-only ---------------------------------------------

class TestTokenFilePermissions(unittest.TestCase):

    def test_refreshed_token_written_0600_even_if_file_was_0644(self):
        with tempfile.TemporaryDirectory() as tmp:
            mod = _load({"GSC_SKIP_OAUTH": "false", "GSC_CONFIG_DIR": tmp})
            token = os.path.join(tmp, "token.json")
            with open(token, "w") as f:
                f.write("{}")
            os.chmod(token, 0o644)
            creds = MagicMock(valid=False, expired=True, refresh_token="r")
            creds.to_json.return_value = '{"token": "refreshed"}'
            creds.refresh.side_effect = lambda _req: setattr(creds, "valid", True)
            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=creds), \
                 patch("gsc_server.build", return_value=MagicMock()), \
                 patch.object(mod, "TOKEN_FILE", token):
                mod.get_gsc_service_oauth()
            self.assertEqual(stat.S_IMODE(os.stat(token).st_mode), 0o600)
            with open(token) as f:
                self.assertEqual(f.read(), '{"token": "refreshed"}')

    def test_new_token_created_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            mod = _load()
            path = os.path.join(tmp, "token.json")
            old = os.umask(0o022)
            try:
                mod._write_token(path, '{"t": 1}')
            finally:
                os.umask(old)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


# --- Control 4 (F5-F7): write gating and removed tools ------------------------------------

class TestToolSurface(unittest.IsolatedAsyncioTestCase):

    async def test_submit_sitemap_blocked_without_destructive_flag(self):
        mod = _load({"GSC_ALLOW_DESTRUCTIVE": "false"})
        service = MagicMock()
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.submit_sitemap("sc-domain:example.com", "https://example.com/sitemap.xml")
        self.assertIn("GSC_ALLOW_DESTRUCTIVE", result)
        service.sitemaps().submit.assert_not_called()

    async def test_submit_sitemap_allowed_with_destructive_flag(self):
        mod = _load({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = MagicMock()
        service.sitemaps().get().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.submit_sitemap("sc-domain:example.com", "https://example.com/sitemap.xml")
        self.assertIn("Successfully submitted", result)

    async def test_removed_tools_are_not_registered(self):
        mod = _load()
        names = {t.name for t in await mod.mcp.list_tools()}
        self.assertIn("list_properties", names)  # the listing itself works
        for removed in ("reauthenticate", "get_creator_info"):
            self.assertNotIn(removed, names)
            self.assertFalse(hasattr(mod, removed), removed)

    async def test_no_tool_tells_the_agent_to_always_call_it(self):
        mod = _load()
        for tool in await mod.mcp.list_tools():
            self.assertNotIn("ALWAYS call", tool.description or "", tool.name)

    async def test_readme_tool_count_matches_registered_tools(self):
        import re
        mod = _load()
        with open(os.path.join(HERE, "README.md")) as f:
            claimed = re.search(r"full list of all (\d+) tools", f.read())
        self.assertIsNotNone(claimed, "README no longer states a tool count")
        self.assertEqual(int(claimed.group(1)), len(await mod.mcp.list_tools()))

    async def test_capabilities_text_does_not_offer_removed_tools(self):
        mod = _load()
        with patch("gsc_server.get_gsc_service", return_value=MagicMock()):
            text = await mod.get_capabilities()
        self.assertNotIn("reauthenticate", text)
        self.assertNotIn("get_creator_info", text)


if __name__ == "__main__":
    unittest.main()


# --- Review round 1 on briebug/mcp-gsc#2 (Greptile) -----------------------------------------

class TestTokenWriteSafety(unittest.TestCase):

    def test_failed_write_keeps_the_existing_token(self):
        """A failed save must not erase the working token (upstream's open('w') did; so did O_TRUNC)."""
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            token = os.path.join(tmp, "token.json")
            with open(token, "w") as f:
                f.write('{"old": "token"}')
            with patch("gsc_server.os.write", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    mod._write_token(token, '{"new": "token"}')
            with open(token) as f:
                self.assertEqual(f.read(), '{"old": "token"}')
            self.assertEqual(os.listdir(tmp), ["token.json"], "no temporary file may be left behind")

    def test_works_where_fchmod_does_not_exist(self):
        """os.fchmod is missing on Windows before Python 3.13."""
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            token = os.path.join(tmp, "token.json")
            with patch.object(mod.os, "fchmod", None, create=True):
                mod._write_token(token, '{"t": 1}')
            with open(token) as f:
                self.assertEqual(f.read(), '{"t": 1}')


class TestPluginConfigEnv(unittest.TestCase):

    def test_configs_do_not_blank_the_users_environment(self):
        """An empty string in a plugin env block overrides what the user exported."""
        for name in TestPinnedLaunch.CONFIGS:
            with open(os.path.join(HERE, name)) as f:
                server = next(iter(json.load(f)["mcpServers"].values()))
            blanks = [k for k, v in server.get("env", {}).items() if v == ""]
            self.assertEqual(blanks, [], name)
            self.assertNotIn("GSC_USE_ADC", server.get("env", {}), name)


class TestLiveTestIsolation(unittest.TestCase):

    def test_live_checks_import_a_fresh_server_under_the_real_environment(self):
        import test_live
        stale = MagicMock(SKIP_OAUTH=True)
        with patch.dict(sys.modules, {"gsc_server": stale}), \
             patch.dict(os.environ, {"GSC_SKIP_OAUTH": "false"}):
            mod = test_live._fresh_server()
        self.assertIsNot(mod, stale)
        self.assertFalse(mod.SKIP_OAUTH)
