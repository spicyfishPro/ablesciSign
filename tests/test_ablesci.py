import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import requests

import ablesci


TOKEN_PAGE = '<meta name="csrf-token" content="test-csrf">'
USER_PAGE = '<span class="mobile-hide able-head-user-vip-username">TestUser</span>'
EMAIL = "tester@private.example.com"
PASSWORD = "secret,semi;colon:equals=value"


def response(payload=None, *, text=None, status=200):
    result = requests.Response()
    result.status_code = status
    result.encoding = "utf-8"
    result._content = (json.dumps(payload) if text is None else text).encode()
    return result


class MemoryNotifier:
    def __init__(self, *args):
        self.log_content = []
        self.notify_enabled = True
        self.notification = None

    def log(self, message, level="info"):
        self.log_content.append(str(message))

    def send_notification(self, content=None):
        self.notification = content


class SignTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.sleep = patch("ablesci.time.sleep")
        self.sleep.start()
        self.notifier = MemoryNotifier()

    def tearDown(self):
        self.sleep.stop()
        self.env.stop()

    def auto(self):
        auto = ablesci.AbleSciAuto(EMAIL, PASSWORD, self.notifier)
        auto.session.close = Mock(wraps=auto.session.close)
        return auto

    def flow(self, sign_payload, login_payload=None):
        auto = self.auto()
        auto.session.get = Mock(side_effect=[
            response(text=TOKEN_PAGE), response(text=USER_PAGE),
            response(sign_payload), response(text=USER_PAGE),
        ])
        auto.session.post = Mock(return_value=response(
            {"code": 0, "msg": "登录成功"} if login_payload is None else login_payload
        ))
        return auto

    def test_csrf_current_legacy_and_missing(self):
        cases = [
            (TOKEN_PAGE, "test-csrf"),
            ('<input name="_csrf" value="legacy">', "legacy"),
            ('<meta name="csrf-token" content=""><input name="_csrf" value="legacy">', "legacy"),
            ("<html>changed</html>", ""),
        ]
        for html, expected in cases:
            with self.subTest(html=html):
                auto = self.auto()
                auto.session.get = Mock(return_value=response(text=html))
                self.assertEqual(auto.get_csrf_token(), expected)
                auto.session.close()

    def test_missing_csrf_stops_before_password_submission(self):
        auto = self.auto()
        auto.session.get = Mock(return_value=response(text="<html></html>"))
        auto.session.post = Mock()
        result = auto.run()
        self.assertEqual((result.status, result.reason), ("failed", "csrf_missing"))
        auto.session.post.assert_not_called()
        auto.session.close.assert_called_once()

    def test_signed_with_same_session_and_original_password(self):
        auto = self.flow({"code": 0, "msg": "签到成功", "data": {"points": 123}})
        result = auto.run()
        self.assertEqual(result, ablesci.AccountResult("te***@***.example.com", "signed"))
        self.assertEqual(auto.session.post.call_args.kwargs["data"]["password"], PASSWORD)
        self.assertEqual(auto.session.post.call_args.kwargs["data"]["_csrf"], "test-csrf")
        self.assertEqual(auto.points, 123)
        self.assertTrue(any("/user/sign" in call.args[0] for call in auto.session.get.call_args_list))
        auto.session.close.assert_called_once()

    def test_already_signed_variants(self):
        for message in ("已经签到", "今日已签到", "签到失败，您今天已于 07:40:00 签到"):
            for code in (0, 1):
                with self.subTest(message=message, code=code):
                    self.assertEqual(self.flow({"code": code, "msg": message}).run().status, "already_signed")

    def test_failure_message_is_not_mistaken_for_already_signed(self):
        auto = self.flow({"code": 1, "msg": "未登录，无法读取已签到信息"})
        self.assertEqual(auto.run().status, "failed")

    def test_bad_password_stops_before_sign_and_redacts_server_message(self):
        auto = self.flow({}, {"code": 1, "msg": f"邮箱 {EMAIL} 密码 {PASSWORD} 错误"})
        result = auto.run()
        self.assertEqual(result.reason, "login_failed")
        self.assertEqual(auto.session.get.call_count, 1)
        logs = "\n".join(self.notifier.log_content)
        for secret in (EMAIL, PASSWORD, "private.example.com"):
            self.assertNotIn(secret, logs)

    def test_captcha_flags_and_rate_limit_stop_without_retry(self):
        cases = [
            ({"error_code": "CAPTCHA_REQUIRED"}, "captcha_required"),
            ({"captcha_required": True}, "captcha_required"),
            ({"verify": 1}, "captcha_required"),
            ({"verify": "1"}, "captcha_required"),
            ({"error_code": "CAPTCHA_INVALID"}, "captcha_invalid"),
            ({"error_code": "CAPTCHA_UNAVAILABLE"}, "captcha_unavailable"),
            ({"error_code": "RATE_LIMITED", "retry_after": 60}, "rate_limited"),
        ]
        for data, expected in cases:
            with self.subTest(data=data):
                auto = self.flow({}, {"code": 1, "data": data})
                self.assertEqual(auto.run().reason, expected)
                auto.session.post.assert_called_once()
                self.assertEqual(auto.session.get.call_count, 1)

    def test_http_errors_non_json_and_timeout_at_each_stage(self):
        for stage in ("csrf", "login", "sign"):
            for outcome, expected in (
                (response(text="busy", status=429), "rate_limited"),
                (response(text="error", status=503), "http_error"),
                (requests.Timeout(PASSWORD), "timeout"),
                (requests.ConnectionError(PASSWORD), "network_error"),
            ):
                with self.subTest(stage=stage, expected=expected):
                    auto = self.flow({"code": 0})
                    if stage == "csrf":
                        auto.session.get.side_effect = [outcome]
                    elif stage == "login":
                        auto.session.post.side_effect = [outcome]
                    else:
                        auto.session.get.side_effect = [response(text=TOKEN_PAGE), response(text=USER_PAGE), outcome]
                    self.assertEqual(auto.run().reason, expected)
        for stage in ("login", "sign"):
            for invalid in (response(text="<html>退出</html>"), response([1, 2])):
                with self.subTest(stage=stage, invalid=invalid.text):
                    auto = self.flow({"code": 0})
                    if stage == "login":
                        auto.session.post.return_value = invalid
                    else:
                        auto.session.get.side_effect = [response(text=TOKEN_PAGE), response(text=USER_PAGE), invalid]
                    self.assertEqual(auto.run().reason, "invalid_response")
        self.assertNotIn(PASSWORD, "\n".join(self.notifier.log_content))

    def test_sign_captcha_and_malformed_status_are_failures(self):
        self.assertEqual(self.flow({"code": 1, "data": {"captcha_required": True}}).run().reason, "captcha_required")
        self.assertEqual(self.flow({"msg": "已签到"}).run().reason, "invalid_response")
        self.assertEqual(self.flow({"code": False}).run().reason, "invalid_response")

    def test_user_info_and_session_cleanup_cannot_overwrite_signed(self):
        auto = self.flow({"code": 0, "msg": "签到成功"})
        auto.get_user_info = Mock(side_effect=RuntimeError(PASSWORD))
        auto.session.get.side_effect = [response(text=TOKEN_PAGE), response({"code": 0, "msg": "签到成功"})]
        auto.session.close.side_effect = RuntimeError(PASSWORD)
        self.assertEqual(auto.run().status, "signed")
        self.assertNotIn(PASSWORD, "\n".join(self.notifier.log_content))

    def test_each_account_has_a_separate_session(self):
        first, second = self.auto(), self.auto()
        first.session.cookies.set("identity", "first")
        self.assertIsNot(first.session, second.session)
        self.assertIsNone(second.session.cookies.get("identity"))
        first.session.close()
        second.session.close()

    def test_account_parsing_preserves_password_punctuation(self):
        value = f"{EMAIL}:{PASSWORD}\nsecond@example.com|pass,with;punctuation"
        with patch.dict(os.environ, {ablesci.ENV_ACCOUNTS: value}):
            self.assertEqual(ablesci.get_accounts(), [(EMAIL, PASSWORD), ("second@example.com", "pass,with;punctuation")])
        for separator in (",", ";"):
            with patch.dict(os.environ, {ablesci.ENV_ACCOUNTS: f"a@example.com:first{separator}b@example.com:second"}):
                self.assertEqual(len(ablesci.get_accounts()), 2)

    def test_env_file_account_with_equals_does_not_log_password(self):
        stream = io.StringIO()
        with patch("ablesci.Path.exists", return_value=True), patch("builtins.open", mock_open(read_data=f"{EMAIL}:{PASSWORD}\n")), contextlib.redirect_stdout(stream):
            ablesci.load_env_file()
        self.assertEqual(os.environ[ablesci.ENV_ACCOUNTS], f"{EMAIL}:{PASSWORD}")
        self.assertNotIn(PASSWORD, stream.getvalue())
        self.assertNotIn(EMAIL, stream.getvalue())

    def run_main(self, outcomes):
        accounts = [(EMAIL, PASSWORD), ("second@example.com", "another-secret")]
        instances = [Mock(), Mock()]
        for instance, outcome in zip(instances, outcomes):
            if isinstance(outcome, Exception):
                instance.run.side_effect = outcome
            else:
                instance.run.return_value = outcome
        notifier = MemoryNotifier()
        with patch("ablesci.load_env_file"), patch("ablesci.get_accounts", return_value=accounts), patch("ablesci.Notifier", return_value=notifier), patch("ablesci.AbleSciAuto", side_effect=instances):
            code = ablesci.main()
        instances[1].run.assert_called_once()
        return code, notifier

    def test_main_all_success_and_already_signed_exit_zero(self):
        outcomes = [ablesci.AccountResult("te***@***.example.com", "signed"), ablesci.AccountResult("se***@***.com", "already_signed")]
        code, notifier = self.run_main(outcomes)
        self.assertEqual(code, 0)
        self.assertIn("2 个成功或已签到，0 个失败", notifier.notification)
        self.assertNotIn(PASSWORD, notifier.notification)
        self.assertNotIn(EMAIL, notifier.notification)

    def test_main_failure_or_exception_does_not_skip_second_account(self):
        for first in (ablesci.AccountResult("te***@***.example.com", "failed", "captcha_required"), RuntimeError(PASSWORD)):
            with self.subTest(first=type(first).__name__):
                code, notifier = self.run_main([first, ablesci.AccountResult("se***@***.com", "signed")])
                self.assertEqual(code, 1)
                self.assertIn("1 个成功或已签到，1 个失败", notifier.notification)
                self.assertNotIn(PASSWORD, "\n".join(notifier.log_content))

    def test_empty_accounts_exit_one_in_main_and_cli(self):
        with patch("ablesci.load_env_file"), patch("ablesci.get_accounts", return_value=[]), patch("ablesci.Notifier", MemoryNotifier):
            self.assertEqual(ablesci.main(), 1)
        env = dict(os.environ, ABLESCI_ACCOUNTS="", SCKEY="", XZKEY="", PUSH_PLUS_TOKEN="")
        process = subprocess.run([sys.executable, str(Path(ablesci.__file__))], env=env, capture_output=True, text=True)
        self.assertEqual(process.returncode, 1)
        self.assertIn("未找到有效的账号配置", process.stdout)


if __name__ == "__main__":
    unittest.main()
