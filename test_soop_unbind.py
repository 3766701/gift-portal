import unittest
from unittest.mock import Mock, patch

import server
from global_login import pubg_cookie_getter_http as getter
from global_login.soop_drops_http import DropsClient, normalize_cookie_header


class Response:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body


class Session:
    def __init__(self, delete_response):
        self.delete_response = delete_response
        self.delete_calls = 0

    def delete(self, *args, **kwargs):
        self.delete_calls += 1
        return self.delete_response


class SoopUnbindTests(unittest.TestCase):
    def test_global_redemption_skips_game_authorization(self):
        class FakeGetter:
            last_kwargs = None

            def get_authorization_info(self, *args, **kwargs):
                type(self).last_kwargs = kwargs
                return {"status": "success"}

            def get_last_login_info(self):
                return None

        original = server.GLOBAL_LOGIN_GETTER_CLASS
        server.GLOBAL_LOGIN_GETTER_CLASS = FakeGetter
        try:
            self.assertEqual(
                server.get_global_login_info("account@example.com", "password", "soop-cookie"),
                {"status": "success"},
            )
        finally:
            server.GLOBAL_LOGIN_GETTER_CLASS = original
        self.assertFalse(FakeGetter.last_kwargs["require_game_authorization"])

    def test_global_login_error_summary_keeps_stage_status_and_error_code(self):
        self.assertEqual(
            server.summarize_global_login_error("FOC signin failed: HTTP 403 {'errorCode': 'account-not-eligible'}"),
            'stage=foc_signin http_status=403 error_code=account-not-eligible',
        )

    def test_global_login_error_summary_omits_response_body(self):
        self.assertEqual(
            server.summarize_global_login_error('OIDC token failed: HTTP 400 {"access_token":"secret"}'),
            'stage=oidc_token http_status=400',
        )

    def test_global_login_error_summary_identifies_oidc_authorization(self):
        self.assertEqual(
            server.summarize_global_login_error('OIDC authorization failed: HTTP 429 rate limited'),
            'stage=oidc_authorize http_status=429',
        )

    def test_global_login_error_summary_uses_recorded_stage(self):
        self.assertEqual(
            server.summarize_global_login_error('unexpected response', 'authorization_result'),
            'stage=authorization_result',
        )

    def test_global_login_failure_message_uses_detail_stage(self):
        self.assertEqual(
            server.global_login_failure_message('stage=krafton_login detail_stage=soop_bind_verify'),
            'SOOP 已授权，但绑定状态尚未生效，请稍后重试。',
        )
        self.assertEqual(
            server.global_login_failure_message('stage=krafton_login detail_stage=password_login'),
            '全球账号登录失败，请确认账号、密码及账号状态后重试。',
        )
        self.assertEqual(
            server.global_login_failure_message('stage=krafton_login detail_stage=password_login_retry'),
            '全球账号登录失败，请确认账号、密码及账号状态后重试。',
        )
        self.assertEqual(
            server.global_login_failure_message('stage=akamai_seed http_status=400 error_code=26'),
            '全球账号登录失败，请确认账号、密码及账号状态后重试。',
        )
        self.assertEqual(
            server.global_login_failure_message('stage=akamai_seed http_status=400 error_code=2'),
            '全球账号登录失败，请确认账号、密码及账号状态后重试。',
        )
        self.assertEqual(
            server.global_login_failure_message('stage=krafton_login http_status=404'),
            '无法找到使用该电子邮箱的账号。',
        )
        self.assertEqual(
            server.global_login_failure_message(
                'stage=akamai_seed http_status=400 error_code=2 '
                'login_error=login-need-to-verify-mfa'
            ),
            '已设置双因素验证。请关闭双因素验证。',
        )

    def test_redemption_trace_context_masks_code_and_account(self):
        self.assertEqual(
            server.redemption_trace_context('95120230F67931A27B58', '3766701@qq.com'),
            'code=9512***7B58 account=3766701@qq.com',
        )

    def test_inventory_import_normalizes_json_cookie(self):
        entries = server.parse_inventory_import(
            '张三|PUBG 补给箱|'
            '{"UserTicket":"user-ticket","AuthTicket":"auth-ticket",'
            '"BbsTicket":"soop_account","BbsSaveTicket":""}'
        )
        self.assertEqual(
            entries[0][2],
            'UserTicket=user-ticket; AuthTicket=auth-ticket; BbsTicket=soop_account; BbsSaveTicket=',
        )
        self.assertEqual(entries[0][1], 'soop_account')

    def test_inventory_import_requires_bbs_ticket(self):
        with self.assertRaisesRegex(ValueError, 'BbsTicket'):
            server.parse_inventory_import('张三|PUBG 补给箱|AuthTicket=value')

    def test_cookie_normalization_preserves_empty_values(self):
        self.assertEqual(
            normalize_cookie_header('AuthTicket=value; BbsSaveTicket='),
            'AuthTicket=value; BbsSaveTicket=',
        )

    def test_business_error_uses_error_level(self):
        with self.assertLogs('gift_portal', level='ERROR') as captured:
            server.log_business_error('SOOP inventory mapping missing')
        self.assertEqual(captured.records[0].levelname, 'ERROR')
        self.assertIn('Business error: SOOP inventory mapping missing', captured.output[0])

    def test_claim_requires_soop_business_success(self):
        client = DropsClient("AuthTicket=value")
        with patch.object(client, "_json", side_effect=[
            {"data": [{"itemCodeIdx": "111198867", "type": "krafton", "itemType": "4", "acctConn": True, "useFlag": "N"}]},
            {"result": 0, "message": "NOT ELIGIBLE"},
        ]):
            with self.assertRaisesRegex(RuntimeError, "NOT ELIGIBLE"):
                client.claim("111198867", confirm=True)

    def test_claim_stops_when_inventory_says_game_account_is_not_connected(self):
        client = DropsClient("AuthTicket=value")
        with patch.object(client, "_json", return_value={
            "data": [{"itemCodeIdx": "111198867", "type": "krafton", "itemType": "4", "acctConn": False, "useFlag": "N"}],
        }) as request:
            with self.assertRaisesRegex(RuntimeError, "connection is not active"):
                client.claim("111198867", confirm=True)
        request.assert_called_once_with(
            "POST", "get_drops_list.php",
            json={"pageNo": 1, "prePageNo": 200, "division": None}, log_body=False,
        )

    @patch.object(server, 'DropsClient')
    def test_stock_claim_fetches_inventory_once_for_all_target_items(self, drops_client):
        client = drops_client.return_value
        client.get_inventory_items.return_value = {
            '111': {'itemCodeIdx': '111', 'type': 'krafton', 'itemType': '4', 'itemName': 'KRAFTON \\u7bb1\\u5b50 A', 'acctConn': True, 'useFlag': 'N'},
            '222': {'itemCodeIdx': '222', 'type': 'krafton', 'itemType': '4', 'itemName': 'KRAFTON 箱子 B', 'acctConn': True, 'useFlag': 'N'},
            '333': {'itemCodeIdx': '333', 'type': 'other', 'itemType': '4', 'itemName': '其他平台奖励', 'acctConn': True, 'useFlag': 'N'},
        }
        client.claim.side_effect = [
            {'result': 1, 'itemCodeIdx': '111'},
            {'result': 1, 'itemCodeIdx': '222'},
        ]

        _, product_name, results = server.claim_soop_stock(('account', 'cookie', 'reward'))

        client.get_inventory_items.assert_called_once_with()
        self.assertEqual({item for item, _ in results}, {'111', '222'})
        self.assertEqual(product_name, 'KRAFTON 箱子 A,KRAFTON 箱子 B')

    def test_soop_item_name_decodes_literal_unicode_escapes(self):
        self.assertEqual(server.decode_soop_item_name('\\u6d4b\\u8bd5'), '测试')

    def test_response_summary_redacts_nested_credentials(self):
        from global_login.soop_drops_http import _response_summary
        self.assertNotIn("keep-secret", _response_summary({"data": {"accessToken": "keep-secret"}}))

    def test_no_soop_binding_does_not_delete(self):
        session = Session(Response(204))
        self.assertFalse(getter.unbind_soop_if_linked(session, {"authentications": [{"provider": "Steam"}]}))
        self.assertEqual(session.delete_calls, 0)

    @patch.object(getter.kid, "profile")
    def test_unbinds_and_verifies_absence(self, profile):
        profile.return_value = Response(200, {"authentications": [{"providerName": "Steam"}]})
        session = Session(Response(204))
        self.assertTrue(getter.unbind_soop_if_linked(session, {"authentications": [{"type": "SOOP"}]}))
        self.assertEqual(session.delete_calls, 1)
        profile.assert_called_once_with(session)

    @patch.object(getter.kid, "profile")
    def test_fails_when_verification_still_shows_soop(self, profile):
        profile.return_value = Response(200, {"authentications": ["SOOP"]})
        session = Session(Response(204))
        with self.assertRaisesRegex(RuntimeError, "SOOP 解绑失败"):
            getter.unbind_soop_if_linked(session, {"authentications": ["SOOP"]})

    def test_artifact_persistence_can_be_suppressed_per_context(self):
        with getter.kid.suppress_artifact_persistence():
            self.assertFalse(getter.kid._PERSIST_ARTIFACTS.get())
        self.assertTrue(getter.kid._PERSIST_ARTIFACTS.get())

    @patch.object(getter.kid, "profile")
    @patch.object(getter.soop_link, "link_soop")
    def test_binds_soop_without_blocking_profile_poll(self, link_soop, profile):
        link_soop.return_value = Mock(status="linked")
        profile.return_value = Response(200, {"authentications": [{"provider": "SOOP"}]})
        session = Session(Response(204))
        getter.bind_soop_to_session(session, "AuthTicket=value")
        link_soop.assert_called_once_with(soop_cookie="AuthTicket=value", confirm=True, krafton_session=session)
        profile.assert_called_once_with(session)

    @patch.object(getter.kid, "profile")
    @patch.object(getter.soop_link, "link_soop")
    def test_binding_callback_is_sufficient_when_profile_would_be_stale(self, link_soop, profile):
        link_soop.return_value = Mock(status="linked")
        profile.return_value = Response(200, {"authentications": [{"provider": "Steam"}]})
        trace = {}
        getter.bind_soop_to_session(Session(Response(204)), "AuthTicket=value", trace=trace)
        self.assertTrue(trace["soop_bind_linked"])

    def test_claim_cookie_uses_only_cookies_valid_for_drops_domain(self):
        session = getter.requests.Session()
        session.cookies.set("AuthTicket", "drops-session", domain=".sooplive.com", path="/")
        session.cookies.set("AuthTicket", "openapi-session", domain="openapi.sooplive.com", path="/")
        cookie = getter.soop_cookie_from_session(
            session, "UserTicket=original-user; AuthTicket=original-auth; BbsSaveTicket=",
        )
        self.assertIn("AuthTicket=drops-session", cookie)
        self.assertNotIn("openapi-session", cookie)

    def test_multiline_cookie_is_normalized(self):
        self.assertEqual(
            normalize_cookie_header("AuthTicket=one\nUserTicket=two\r\nBbsTicket=three"),
            "AuthTicket=one; UserTicket=two; BbsTicket=three",
        )

    def test_detects_soop_in_an_unrecognized_authentication_field(self):
        self.assertTrue(getter.profile_has_soop_authentication({"authentications": [{"connectionType": "SOOP"}]}))


if __name__ == "__main__":
    unittest.main()
