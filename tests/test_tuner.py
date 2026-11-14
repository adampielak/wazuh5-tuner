"""Tests for wazuh5-tuner.py. Run: python3 -m unittest discover -s tests"""
import importlib.util
import json
import pathlib
import threading
import unittest
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("tuner", ROOT / "wazuh5-tuner.py")
t = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(t)


def findings(text):
    return [(level, line, msg) for level, line, msg in t.check_text(text)]


def levels(text):
    return [f[0] for f in findings(text)]


class ParamTable(unittest.TestCase):
    def test_table_matches_data_file(self):
        data = json.loads((ROOT / "data" / "params.json").read_text())
        for section in data.values():
            for p in section["params"]:
                del p["src"], p["doc"]  # provenance stays in the data file only
        self.assertEqual(data, t.PARAMS)

    def test_defaults_in_range(self):
        for key, p in t.ALL_PARAMS.items():
            self.assertTrue(p["desc"], key)
            if p["type"] == "bool":
                self.assertIsInstance(p["default"], bool, key)
            elif p["default"] is not None:
                self.assertLessEqual(p["min"], p["default"], key)
                self.assertLessEqual(p["default"], p["max"], key)
                if p.get("gap"):
                    self.assertTrue(p["default"] == 0 or p["default"] >= p["gap"], key)

    def test_default_values_pass_every_rule(self):
        self.assertEqual(t.cross_check({}), [])

    def test_presets_validate(self):
        for name, preset in t.PRESETS.items():
            self.assertEqual(t.validate(preset["values"])[1], [], name)

    def test_other_keys_do_not_overlap_tuned_keys(self):
        self.assertFalse(set(t.OTHER_KEYS) & set(t.ALL_PARAMS))


class Validate(unittest.TestCase):
    def test_int_range(self):
        self.assertEqual(t.validate({"remoted.worker_pool": "8"}), ({"remoted.worker_pool": 8}, []))
        self.assertTrue(t.validate({"remoted.worker_pool": 17})[1])
        self.assertTrue(t.validate({"remoted.worker_pool": 0})[1])

    def test_rejects_non_integers(self):
        for bad in ("4 # x", "4.0", "+4", "", True, "0x10"):
            self.assertTrue(t.validate({"remoted.worker_pool": bad})[1], bad)

    def test_gap(self):
        # No rc2 key keeps a gap after the docs narrowed the ranges; check the rule itself.
        spec = {"min": 0, "max": 100, "gap": 10}
        self.assertIsNone(t._int_ok(spec, 0))
        self.assertIsNone(t._int_ok(spec, 10))
        self.assertTrue(t._int_ok(spec, 9))

    def test_bool(self):
        self.assertEqual(t.validate({"analysisd.dumper_enabled": "TRUE"})[0], {"analysisd.dumper_enabled": True})
        self.assertTrue(t.validate({"analysisd.dumper_enabled": 1})[1])

    def test_none_means_unset(self):
        self.assertEqual(t.validate({"wazuh_modules.manager_task_executor_threads": None}), ({}, []))

    def test_unknown_key(self):
        self.assertTrue(t.validate({"remoted.nope": 1})[1])

    def test_cross_rules(self):
        self.assertTrue(t.validate({"remoted.verify_msg_id": 1})[1])
        self.assertEqual(t.validate({"remoted.verify_msg_id": 1, "remoted.worker_pool": 1})[1], [])
        self.assertTrue(t.validate({"wazuh_modules.manager_task_delete_timeout": 300})[1])


class Generate(unittest.TestCase):
    def test_changed_only(self):
        out = t.generate({"remoted.worker_pool": 8, "remoted.sender_pool": t.ALL_PARAMS["remoted.sender_pool"]["default"]})
        self.assertIn("remoted.worker_pool=8\n", out)
        self.assertNotIn("remoted.sender_pool=", out)

    def test_bool_and_null(self):
        out = t.generate({"analysisd.dumper_enabled": True}, changed_only=False)
        self.assertIn("analysisd.dumper_enabled=true", out)
        self.assertNotIn("manager_task_executor_threads", out)

    def test_full_file_checks_clean(self):
        out = t.generate({}, changed_only=False)
        self.assertEqual([f for f in findings(out) if f[0] != "INFO"], [])


class Check(unittest.TestCase):
    def test_trailing_space_and_inline_comment_are_fatal(self):
        self.assertEqual(levels("remoted.worker_pool=4 \n"), ["ERROR"])
        self.assertEqual(levels("remoted.worker_pool=4 # c\n"), ["ERROR"])

    def test_empty_value_is_fatal(self):
        self.assertEqual(levels("remoted.worker_pool=\n"), ["ERROR"])

    def test_c_first_line_wins(self):
        f = findings("remoted.worker_pool=4\nremoted.worker_pool=99\n")
        self.assertEqual([x[0] for x in f], ["WARN"])
        self.assertIn("line 1", f[0][2])

    def test_engine_last_line_wins(self):
        f = findings("analysisd.dumper_enabled=yes\nanalysisd.dumper_enabled=true\n")
        self.assertEqual([x[0] for x in f], ["WARN"])
        self.assertEqual(levels("analysisd.dumper_enabled=true\nanalysisd.dumper_enabled=yes\n"), ["WARN", "ERROR"])

    def test_engine_comment_and_quotes(self):
        self.assertEqual(levels("analysisd.dumper_enabled=\"true\" # on\n"), [])

    def test_engine_type_only_keys_warn(self):
        self.assertEqual(levels("analysisd.debug=5\n"), ["WARN"])
        self.assertEqual(levels("analysisd.debug=x\n"), ["ERROR"])

    def test_whitespace_led_lines(self):
        self.assertEqual(levels("\tremoted.worker_pool=99\n"), ["WARN"])
        self.assertEqual(levels(" remoted.worker_pool=99\n"), ["WARN"])

    def test_unknown_and_other_keys(self):
        self.assertEqual(levels("remoted.nope=1\n"), ["WARN"])
        other = next(iter(t.OTHER_KEYS))
        self.assertEqual(levels(f"{other}=1\n"), ["INFO"])

    def test_not_key_value(self):
        self.assertEqual(levels("garbage\n"), ["WARN"])

    def test_long_line(self):
        self.assertIn("ERROR", levels("#" + "x" * 1100 + "\n"))

    def test_cross_rules(self):
        self.assertEqual(levels("remoted.verify_msg_id=1\n"), ["ERROR"])
        self.assertEqual(levels("remoted.verify_msg_id=1\nremoted.worker_pool=1\n"), [])
        self.assertEqual(levels("wazuh_modules.manager_task_delete_timeout=300\n"), ["ERROR"])


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = t.Server(("127.0.0.1", 0), t.Handler)
        cls.server.RequestHandlerClass.log_message = lambda *a: None
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def req(self, path, body=None):
        r = urllib.request.Request(self.base + path, data=body, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read().decode()

    def test_page(self):
        code, body = self.req("/")
        self.assertEqual(code, 200)
        self.assertNotIn("__PARAMS__", body)
        self.assertIn("wazuh-manager-internal-options.conf", body)

    def test_api(self):
        self.assertEqual(json.loads(self.req("/api/params")[1]), t.PARAMS)
        self.assertEqual(set(json.loads(self.req("/api/presets")[1])), set(t.PRESETS))
        self.assertEqual(self.req("/nope")[0], 404)

    def test_generate(self):
        code, body = self.req("/api/generate", json.dumps({"values": {"remoted.worker_pool": 8}}).encode())
        self.assertEqual(code, 200)
        self.assertIn("remoted.worker_pool=8", json.loads(body)["config"])
        self.assertEqual(self.req("/api/generate", json.dumps({"values": {"remoted.worker_pool": 99}}).encode())[0], 400)
        self.assertEqual(self.req("/api/generate", b"not json")[0], 400)
        self.assertEqual(self.req("/api/generate", b"x" * 70000)[0], 413)

    def test_check(self):
        code, body = self.req("/api/check", b"remoted.worker_pool=4 \n")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["findings"][0]["level"], "ERROR")


if __name__ == "__main__":
    unittest.main()
