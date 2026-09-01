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
    def test_inventory_import_normalizes_json_cookie(self):
        entries = server.parse_inventory_import(
            '张三|soop_account|PUBG 补给箱|111198867|'
            '{"UserTicket":"user-ticket","AuthTicket":"auth-ticket",'
            '"BbsTicket":"bbs-ticket","BbsSaveTicket":""}'
        )
        self.assertEqual(
            entries[0][2],
            'UserTicket=user-ticket; AuthTicket=auth-ticket; BbsTicket=bbs-ticket; BbsSaveTicket=',
        )

    def test_cookie_normalization_preserves_empty_values(self):
        self.assertEqual(
            normalize_cookie_header('AuthTicket=value; BbsSaveTicket='),
            'AuthTicket=value; BbsSaveTicket=',
        )

    def test_inventory_import_accepts_escaped_underscore_cookie_json(self):
        entries = server.parse_inventory_import(
            '张三|soop_account|PUBG 补给箱|111198867|'
            r'{"user\_ticket":"user-ticket","auth\_ticket":"auth-ticket",'
            r'"bbs\_ticket":"bbs-ticket","bbs\_save\_ticket":""}'
        )
        self.assertEqual(
            entries[0][2],
            'UserTicket=user-ticket; AuthTicket=auth-ticket; BbsTicket=bbs-ticket; BbsSaveTicket=',
        )

    def test_business_error_uses_error_level(self):
        with self.assertLogs('gift_portal', level='ERROR') as captured:
            server.log_business_error('SOOP inventory mapping missing')
        self.assertEqual(captured.records[0].levelname, 'ERROR')
        self.assertIn('Business error: SOOP inventory mapping missing', captured.output[0])

    def test_claim_requires_soop_business_success(self):
        client = DropsClient("AuthTicket=value")
        with patch.object(client, "_json", return_value={"result": 0, "message": "NOT ELIGIBLE"}):
            with self.assertRaisesRegex(RuntimeError, "NOT ELIGIBLE"):
                client.claim("111198867", confirm=True)

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
    def test_binds_soop_and_verifies_profile(self, link_soop, profile):
        link_soop.return_value = Mock(status="linked")
        profile.return_value = Response(200, {"authentications": [{"provider": "SOOP"}]})
        session = Session(Response(204))
        getter.bind_soop_to_session(session, "AuthTicket=value")
        link_soop.assert_called_once_with(soop_cookie="AuthTicket=value", confirm=True, krafton_session=session)

    def test_multiline_cookie_is_normalized(self):
        self.assertEqual(
            normalize_cookie_header("AuthTicket=one\nUserTicket=two\r\nBbsTicket=three"),
            "AuthTicket=one; UserTicket=two; BbsTicket=three",
        )

    def test_detects_soop_in_an_unrecognized_authentication_field(self):
        self.assertTrue(getter.profile_has_soop_authentication({"authentications": [{"connectionType": "SOOP"}]}))


if __name__ == "__main__":
    unittest.main()
