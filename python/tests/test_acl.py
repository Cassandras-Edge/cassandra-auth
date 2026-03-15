"""Tests for the Python ACL enforcer — validates parity with the TypeScript implementation."""

from cassandra_mcp_auth.acl import Enforcer, PolicyLine, _build_policies


def _make_test_config():
    """Mirror of env/acl.yaml for testing."""
    return {
        "default": "deny",
        "groups": {
            "creators": {
                "services": {
                    "yt-mcp": {
                        "access": "allow",
                        "tools": {
                            "deny": ["watch_later_sync", "watch_later_status"],
                        },
                    },
                },
            },
            "internal": {
                "services": {
                    "yt-mcp": {
                        "access": "allow",
                    },
                },
            },
        },
        "users": {
            "andrew@raftesalo.net": {
                "role": "admin",
                "services": "*",
            },
            "arrosskuroi98@gmail.com": {
                "role": "user",
                "groups": ["creators"],
            },
        },
        "domains": {
            "bluechipcapitalinvestments.com": {
                "role": "user",
                "groups": ["internal"],
            },
        },
    }


def _build_enforcer():
    policies = _build_policies(_make_test_config())
    return Enforcer(policies)


class TestEnforcer:
    def test_admin_allowed_all(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("andrew@raftesalo.net", "yt-mcp", "transcribe")
        assert result.allowed is True

    def test_admin_allowed_any_service(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("andrew@raftesalo.net", "pushover", "send")
        assert result.allowed is True

    def test_admin_allowed_watch_later(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("andrew@raftesalo.net", "yt-mcp", "watch_later_sync")
        assert result.allowed is True

    def test_creators_allowed_transcribe(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("arrosskuroi98@gmail.com", "yt-mcp", "transcribe")
        assert result.allowed is True

    def test_creators_denied_watch_later_sync(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("arrosskuroi98@gmail.com", "yt-mcp", "watch_later_sync")
        assert result.allowed is False
        assert result.reason == "explicitly denied"

    def test_creators_denied_watch_later_status(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("arrosskuroi98@gmail.com", "yt-mcp", "watch_later_status")
        assert result.allowed is False

    def test_domain_internal_allowed(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("user@bluechipcapitalinvestments.com", "yt-mcp", "transcribe")
        assert result.allowed is True

    def test_domain_internal_allowed_watch_later(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce(
            "user@bluechipcapitalinvestments.com", "yt-mcp", "watch_later_sync"
        )
        assert result.allowed is True

    def test_unknown_user_denied(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("nobody@example.com", "yt-mcp", "transcribe")
        assert result.allowed is False
        assert result.reason == "no matching policy"

    def test_creators_denied_other_service(self):
        enforcer = _build_enforcer()
        result = enforcer.enforce("arrosskuroi98@gmail.com", "pushover", "send")
        assert result.allowed is False

    def test_allowed_tools_admin(self):
        enforcer = _build_enforcer()
        all_tools = [
            "transcribe", "job_status", "search", "list_transcripts",
            "read_transcript", "yt_search", "list_channel_videos",
            "get_metadata", "get_comments", "watch_later_sync", "watch_later_status",
        ]
        allowed = enforcer.allowed_tools("andrew@raftesalo.net", "yt-mcp", all_tools)
        assert len(allowed) == 11

    def test_allowed_tools_creators(self):
        enforcer = _build_enforcer()
        all_tools = [
            "transcribe", "job_status", "search", "list_transcripts",
            "read_transcript", "yt_search", "list_channel_videos",
            "get_metadata", "get_comments", "watch_later_sync", "watch_later_status",
        ]
        allowed = enforcer.allowed_tools("arrosskuroi98@gmail.com", "yt-mcp", all_tools)
        # 11 total - 2 denied (watch_later_sync, watch_later_status) = 9
        assert len(allowed) == 9
        assert "watch_later_sync" not in allowed
        assert "watch_later_status" not in allowed

    def test_allowed_tools_unknown_user(self):
        enforcer = _build_enforcer()
        all_tools = ["transcribe", "search"]
        allowed = enforcer.allowed_tools("nobody@example.com", "yt-mcp", all_tools)
        assert len(allowed) == 0
