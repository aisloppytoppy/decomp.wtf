"""Tests for Streamable HTTP MCP Bearer token management, authentication, hardening, and CLI commands."""

import json
import os
import time
import pytest
from starlette.testclient import TestClient

from decompnet.app.engine import RomNetwork
from decompnet.app.server import build, _parse_ttl
from decompnet.app import cli, tools
from decompnet.network import NetworkError
from mcp.server.mcpserver.exceptions import ToolError

PORT, SECRET = 6498, "mcp-test-secret-1234"


def test_parse_ttl():
    assert _parse_ttl(None) is None
    assert _parse_ttl("") is None
    assert _parse_ttl("never") is None
    assert _parse_ttl(0) is None
    assert _parse_ttl("0") is None
    assert _parse_ttl(3600) == 3600.0
    assert _parse_ttl("60s") == 60.0
    assert _parse_ttl("10m") == 600.0
    assert _parse_ttl("24h") == 86400.0
    assert _parse_ttl("7d") == 7 * 86400.0
    assert _parse_ttl("30d") == 30 * 86400.0


def test_engine_bearer_token_management(tmp_path):
    net = RomNetwork(tmp_path / "decomp.db", tmp_path)

    # Setup token with custom string
    agent, token = net.setup_bearer_token("cursor-user", "dn_mycustomtoken123", scope="full")
    assert agent.name == "cursor-user"
    assert token == "dn_mycustomtoken123"
    assert agent.scope == "full"
    assert net.is_chat(agent)

    # Auto-prepend dn_ if missing
    agent2, token2 = net.setup_bearer_token("claude-desktop", "rawtoken999", scope="read")
    assert token2 == "dn_rawtoken999"
    assert agent2.scope == "read"

    # List tokens
    tokens = net.list_chat_tokens()
    assert len(tokens) >= 2
    names = [t["name"] for t in tokens]
    assert "cursor-user" in names
    assert "claude-desktop" in names

    # Token prefix masking
    cursor_tok = next(t for t in tokens if t["name"] == "cursor-user")
    assert cursor_tok["token_prefix"].startswith("dn_")
    assert "..." in cursor_tok["token_prefix"]
    assert cursor_tok["scope"] == "full"
    assert cursor_tok["last_seen"] is None

    claude_tok = next(t for t in tokens if t["name"] == "claude-desktop")
    assert claude_tok["scope"] == "read"

    # Authenticate token and record telemetry (last_ip, user_agent)
    authed = net.authenticate("dn_mycustomtoken123", client_ip="192.168.1.50", user_agent="Cursor/0.40")
    assert authed is not None
    assert authed.name == "cursor-user"
    assert authed.scope == "full"

    # Verify telemetry persisted
    tokens_after = net.list_chat_tokens()
    cursor_after = next(t for t in tokens_after if t["name"] == "cursor-user")
    assert cursor_after["last_ip"] == "192.168.1.50"
    assert cursor_after["user_agent"] == "Cursor/0.40"
    assert cursor_after["last_seen"] is not None

    # Revoke token by ID
    c_id = cursor_after["id"]
    assert net.revoke_chat_token(c_id) is True
    with pytest.raises(NetworkError, match="invalid API token"):
        net.authenticate("dn_mycustomtoken123")

    # Revoke token by name
    assert net.revoke_chat_token("claude-desktop") is True
    with pytest.raises(NetworkError, match="invalid API token"):
        net.authenticate("dn_rawtoken999")

    # Revoking non-existent returns False
    assert net.revoke_chat_token("nonexistent") is False

    # Test revoke all
    net.setup_bearer_token("t1", "dn_token1")
    net.setup_bearer_token("t2", "dn_token2")
    assert len(net.list_chat_tokens()) >= 2
    revoked_count = net.revoke_all_chat_tokens()
    assert revoked_count >= 2
    assert len(net.list_chat_tokens()) == 0


def test_token_expiration_and_ttl(tmp_path):
    net = RomNetwork(tmp_path / "decomp.db", tmp_path)

    # Token with short TTL (0.15s)
    agent, token = net.chat_agent("ephemeral-agent", ttl_seconds=0.15)
    assert agent.name == "ephemeral-agent"

    # Immediately authenticate: should succeed
    authed = net.authenticate(token)
    assert authed.name == "ephemeral-agent"

    # Wait for TTL expiration
    time.sleep(0.2)

    # Should raise expired API token
    with pytest.raises(NetworkError, match="expired API token"):
        net.authenticate(token)

    # Should show is_expired in list_chat_tokens
    tokens = net.list_chat_tokens()
    ephemeral = next(t for t in tokens if t["name"] == "ephemeral-agent")
    assert ephemeral["is_expired"] is True


def test_token_scope_enforcement(tmp_path):
    net = RomNetwork(tmp_path / "decomp.db", tmp_path)
    # Read-only token
    read_agent, read_tok = net.chat_agent("read-only-observer", scope="read")
    assert read_agent.scope == "read"

    # Full access token
    full_agent, full_tok = net.chat_agent("full-agent", scope="full")
    assert full_agent.scope == "full"

    # Verify call() scope enforcement in tools.py
    # Read action allowed
    res_info = tools.call(net, read_agent, "", "guide", {"topic": "workflow"})
    assert not res_info.startswith("error: read-only token")

    # Mutating action blocked for read-only agent
    res_claim = tools.call(net, read_agent, "", "claim_function", {"function": "test_func"})
    assert "read-only token cannot execute mutating action" in res_claim


def test_server_http_mcp_token_endpoints(tmp_path):
    home = tmp_path
    (home / ".decomp").mkdir(parents=True, exist_ok=True)
    net = RomNetwork(home / ".decomp" / "decomp.db", home)
    mcp, manager, security = build(net, home / ".decomp", PORT, SECRET)
    app = mcp.streamable_http_app(transport_security=security, host="127.0.0.1")

    # Anonymous client: 401
    anon = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    assert anon.get("/api/agents/tokens").status_code == 401
    assert anon.post("/api/agents/token", json={"name": "test"}).status_code == 401

    # Authenticated via Cookie
    client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    client.cookies.set("decomp_live", SECRET)

    # Write requires X-Decomp: 1 when using cookie
    assert client.post("/api/agents/token", json={"name": "test"}).status_code == 403

    # Create auto-generated token with scope and ttl
    r = client.post(
        "/api/agents/token",
        json={"name": "test-agent", "scope": "read", "ttl": "7d"},
        headers={"X-Decomp": "1"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["agent"] == "test-agent"
    assert data["token"].startswith("dn_")
    assert data["scope"] == "read"
    assert data["expires_at"] is not None
    assert "mcpServers" in data["configs"]["mcp_json"]
    assert "decomp" in data["configs"]["mcp_json"]["mcpServers"]
    assert data["configs"]["mcp_json"]["mcpServers"]["decomp"]["type"] == "http"
    assert "Authorization" in data["configs"]["mcp_json"]["mcpServers"]["decomp"]["headers"]
    assert data["configs"]["claude_command"].startswith("claude mcp add --transport http")

    # Create custom token with full scope
    r = client.post(
        "/api/agents/token",
        json={"name": "custom-agent", "token": "dn_customsecret888", "scope": "full"},
        headers={"X-Decomp": "1"},
    )
    assert r.status_code == 200
    assert r.json()["token"] == "dn_customsecret888"
    assert r.json()["scope"] == "full"

    # List tokens via cookie
    r = client.get("/api/agents/tokens")
    assert r.status_code == 200
    tokens = r.json()["tokens"]
    assert any(t["name"] == "custom-agent" for t in tokens)
    assert any(t["name"] == "test-agent" for t in tokens)
    # Check token masking in list
    t_obj = next(t for t in tokens if t["name"] == "custom-agent")
    assert t_obj["token_prefix"].startswith("dn_")
    assert "..." in t_obj["token_prefix"]

    # Authenticated via X-Decomp-Secret header (no cookie needed, no X-Decomp needed)
    secret_client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    r = secret_client.get("/api/agents/tokens", headers={"X-Decomp-Secret": SECRET})
    assert r.status_code == 200

    r = secret_client.post("/api/agents/token", json={"name": "header-agent"}, headers={"X-Decomp-Secret": SECRET})
    assert r.status_code == 200
    assert r.json()["agent"] == "header-agent"

    # Authenticated via Authorization: Bearer <secret> (no cookie needed)
    bearer_admin = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    r = bearer_admin.get("/api/agents/tokens", headers={"Authorization": f"Bearer {SECRET}"})
    assert r.status_code == 200

    # Revoke by name via POST /api/agents/token/revoke
    r = client.post("/api/agents/token/revoke", json={"name": "custom-agent"}, headers={"X-Decomp": "1"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    with pytest.raises(NetworkError, match="invalid API token"):
        net.authenticate("dn_customsecret888")

    # Revoke by ID via DELETE /api/agents/token
    tokens_now = client.get("/api/agents/tokens").json()["tokens"]
    target_id = next(t["id"] for t in tokens_now if t["name"] == "header-agent")
    r = client.delete(f"/api/agents/token?id={target_id}", headers={"X-Decomp": "1"})
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Revoke all tokens via POST /api/agents/tokens/revoke-all
    r = client.post("/api/agents/tokens/revoke-all", headers={"X-Decomp": "1"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["revoked_count"] >= 1

    # Verify tokens list is now empty
    tokens_empty = client.get("/api/agents/tokens").json()["tokens"]
    assert len(tokens_empty) == 0


def test_env_token_and_allowed_hosts(tmp_path, monkeypatch):
    home = tmp_path
    (home / ".decomp").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DECOMP_MCP_TOKEN", "dn_preseededtoken123")
    monkeypatch.setenv("DECOMP_ALLOWED_HOSTS", "customhost.local:6498, 192.168.1.10:6498")

    net = RomNetwork(home / ".decomp" / "decomp.db", home)
    mcp, manager, security = build(net, home / ".decomp", PORT, SECRET)

    # Check that preseeded token exists in DB
    agent = net.authenticate("dn_preseededtoken123")
    assert agent is not None
    assert agent.name == "env-token"

    # Check that customhost is allowed by security
    assert "customhost.local:6498" in security.allowed_hosts
    assert "192.168.1.10:6498" in security.allowed_hosts


def test_cli_token_parser():
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    tok = sub.add_parser("token")
    tok.add_argument("action", choices=["create", "list", "revoke", "revoke-all"], nargs="?", default="create")
    tok.add_argument("--name", default="chat")
    tok.add_argument("--token", default=None)
    tok.add_argument("--scope", choices=["full", "read"], default="full")
    tok.add_argument("--ttl", default=None)
    tok.add_argument("--id", default=None)
    tok.add_argument("--all", action="store_true")
    tok.add_argument("--json", action="store_true")

    args = parser.parse_args(["token", "create", "--name", "cursor", "--token", "dn_test123", "--scope", "read", "--ttl", "30d"])
    assert args.cmd == "token"
    assert args.action == "create"
    assert args.name == "cursor"
    assert args.token == "dn_test123"
    assert args.scope == "read"
    assert args.ttl == "30d"

    args_list = parser.parse_args(["token", "list", "--json"])
    assert args_list.action == "list"
    assert args_list.json is True

    args_revoke = parser.parse_args(["token", "revoke", "--id", "12"])
    assert args_revoke.action == "revoke"
    assert args_revoke.id == "12"

    args_revoke_all = parser.parse_args(["token", "revoke-all"])
    assert args_revoke_all.action == "revoke-all"


@pytest.mark.anyio
async def test_agent_of_project_resolution(tmp_path):
    home = tmp_path
    (home / ".decomp").mkdir(parents=True, exist_ok=True)
    net = RomNetwork(home / ".decomp" / "decomp.db", home)
    mcp, manager, security = build(net, home / ".decomp", PORT, SECRET)
    agent, token = net.chat_agent("test-agent")

    class MockCtx:
        headers = {"authorization": f"Bearer {token}"}
        request = None

    # 1. When no project exists, static tools (guide) succeed without requiring a project
    res_guide_early = await mcp.call_tool("guide", {"topic": "workflow"}, context=MockCtx())
    assert res_guide_early is not None
    guide_early_text = "\n".join(getattr(b, "text", "") for b in res_guide_early.content)
    assert "[Auto-selected project" not in guide_early_text
    assert "matching loop" in guide_early_text

    # But project-dependent work tools and chat tools raise ToolError with "no project is open..."
    with pytest.raises(ToolError, match="no project is open"):
        await mcp.call_tool("project_info", {}, context=MockCtx())

    with pytest.raises(ToolError, match="no project is open"):
        await mcp.call_tool("progress", {}, context=MockCtx())

    # 2. Insert a project into the database
    cfg = json.dumps({"compiler": {"toolchain": "ido-5.3"}, "platform": "n64"})
    with net.store.tx() as conn:
        conn.execute(
            "INSERT INTO projects (slug, name, arch, root, config) VALUES (?, ?, ?, ?, ?)",
            ("sample-slug", "Sample Game", "mips", str(home), cfg),
        )

    # 3. Static tools still do not trigger auto-selection even with project present
    res_guide = await mcp.call_tool("guide", {"topic": "workflow"}, context=MockCtx())
    assert res_guide is not None
    guide_text = "\n".join(getattr(b, "text", "") for b in res_guide.content)
    assert "[Auto-selected project" not in guide_text
    assert "matching loop" in guide_text
    assert manager.project_of(agent.id) is None

    # 4. Project-dependent work tool triggers auto-selection, announces, and persists assignment
    res_info = await mcp.call_tool("project_info", {}, context=MockCtx())
    assert res_info is not None
    info_text = "\n".join(getattr(b, "text", "") for b in res_info.content)
    assert "[Auto-selected project: sample-slug]" in info_text
    assert "Sample Game" in info_text

    # 5. Verify assignment is persisted to manager and settings
    assert manager.project_of(agent.id) == "sample-slug"

    # 6. Chat tools (progress, open_gui, list_projects) are immediately aligned without error
    res_prog = await mcp.call_tool("progress", {}, context=MockCtx())
    prog_text = "\n".join(getattr(b, "text", "") for b in res_prog.content)
    assert "sample-slug" in prog_text
    # Does not repeat auto-selection banner since already persisted
    assert "[Auto-selected project: sample-slug]" not in prog_text

    res_gui = await mcp.call_tool("open_gui", {}, context=MockCtx())
    gui_text = "\n".join(getattr(b, "text", "") for b in res_gui.content)
    assert "#/p/sample-slug" in gui_text

    res_list = await mcp.call_tool("list_projects", {}, context=MockCtx())
    list_text = "\n".join(getattr(b, "text", "") for b in res_list.content)
    assert "Open now: sample-slug" in list_text

    # 7. When the assigned project is deleted, static tools clean up stale state and succeed
    with net.store.tx() as conn:
        conn.execute("DELETE FROM projects WHERE slug = ?", ("sample-slug",))

    res_guide_post_del = await mcp.call_tool("guide", {"topic": "workflow"}, context=MockCtx())
    assert res_guide_post_del is not None
    assert manager.project_of(agent.id) is None
    settings_data = json.loads((home / ".decomp" / "settings.json").read_text())
    assert settings_data.get("last_project") is None

    # Project-dependent tools fail again with no projects in DB
    with pytest.raises(ToolError, match="no project is open"):
        await mcp.call_tool("project_info", {}, context=MockCtx())

