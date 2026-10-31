"""Dependency agent's OSV.dev path, using a mocked HTTP transport (no network)."""
import httpx

from app.agents import dependency
from app.services.preprocessing import Dependency


def test_osv_lookup_parses_severity_and_fixed_version(monkeypatch):
    def handler(request: httpx.Request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-j8r2-6x86-q33q"}]}, {}]})
        if request.url.path.startswith("/v1/vulns/"):
            return httpx.Response(200, json={
                "id": "GHSA-j8r2-6x86-q33q", "aliases": ["CVE-2023-32681"], "summary": "Proxy-Authorization leak",
                "database_specific": {"severity": "MODERATE"},
                "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}]}]})
        return httpx.Response(404)

    real_client = httpx.Client
    monkeypatch.setattr(dependency.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    deps = [Dependency("requests", "2.25.1", "PyPI", "requirements.txt", 1),
            Dependency("flask", "3.0.0", "PyPI", "requirements.txt", 2)]
    result = dependency.DependencyAgent()._osv(deps)
    assert len(result) == 1
    dep, adv = result[0]
    assert dep.name == "requests" and adv["id"] == "CVE-2023-32681"
    assert adv["severity"] == "Medium" and adv["fixed"] == "2.31.0"


def test_osv_failure_falls_back_to_none(monkeypatch):
    real_client = httpx.Client
    monkeypatch.setattr(dependency.httpx, "Client",
                        lambda **kw: real_client(transport=httpx.MockTransport(lambda r: httpx.Response(503))))
    assert dependency.DependencyAgent()._osv([Dependency("requests", "2.25.1", "PyPI", "r.txt", 1)]) is None
