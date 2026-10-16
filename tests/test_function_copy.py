"""Tests for copying function details, context headers, and copy endpoints."""

import json
import pytest
from starlette.testclient import TestClient

from decompnet.app.engine import RomNetwork
from decompnet.app.server import build

PORT, SECRET = 6498, "s3cret-copy-tests"


@pytest.fixture
def test_setup(tmp_path):
    home = tmp_path / "home"
    (home / ".decomp").mkdir(parents=True)
    net = RomNetwork(home / ".decomp" / "decomp.db", home)
    mcp, manager, security = build(net, home / ".decomp", PORT, SECRET)
    app = mcp.streamable_http_app(transport_security=security, host="127.0.0.1")
    client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    client.cookies.set("decomp_live", SECRET)

    # Insert a mock project and function into db
    with net.store.tx() as db:
        pid = db.execute(
            "INSERT INTO projects(slug, name, description, arch, big_endian, root, config) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            ("testproj", "Test Project", "Demo description", "mips", 1, str(home),
             json.dumps({"compiler": {"toolchain": "gcc-2.7.2-kmc"}}))
        ).lastrowid
        db.execute(
            "INSERT INTO context_versions(project_id, version, header, agent_id, message, created_at, unit) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (pid, 1, "typedef int s32;\ntypedef unsigned int u32;\nvoid helper(void);\n", None, "initial", 1000.0, "")
        )
        fn_id = db.execute(
            "INSERT INTO functions(project_id, name, vram, rom_offset, size, n_insns, status, asm, relocs) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (pid, "test_func", 0x80001000, 0x1000, 16, 4, "open", "jr $ra\nnop\n", "[]")
        ).lastrowid
        db.execute(
            "INSERT INTO notes(project_id, function_id, text, created_at) "
            "VALUES(?, ?, ?, ?)",
            (pid, fn_id, "Test note from previous agent", 1001.0)
        )

    return client, net, pid, fn_id


def test_function_detail_includes_context_and_notes(test_setup):
    client, net, pid, fn_id = test_setup
    r = client.get("/api/function?slug=testproj&name=test_func")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "test_func"
    assert "context" in data
    assert "typedef int s32;" in data["context"]
    assert data["context_version"] == 1
    assert data["asm"] == "jr $ra\nnop\n"
    assert len(data["notes"]) == 1
    assert data["notes"][0]["text"] == "Test note from previous agent"


def test_api_context_endpoint(test_setup):
    client, net, pid, fn_id = test_setup
    r = client.get("/api/context?slug=testproj&function=test_func")
    assert r.status_code == 200
    data = r.json()
    assert "context" in data
    assert "typedef int s32;" in data["context"]
