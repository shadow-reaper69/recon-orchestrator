"""Unit tests for tool parsers with synthetic test fixtures."""

from recon.parsers.httpx_parser import parse_httpx_jsonl
from recon.parsers.nmap_parser import parse_nmap_xml
from recon.parsers.nuclei_parser import parse_nuclei_jsonl
from recon.parsers.subfinder_parser import parse_subfinder_output


def test_subfinder_parser_plain_and_json():
    synthetic_output = (
        "sub1.example.com\n"
        "sub2.example.com\n"
        '{"host": "api.example.com"}\n'
        "sub1.example.com\n"  # duplicate
        "   \n"
        "invalid-domain..com\n"
    )
    result = parse_subfinder_output(synthetic_output)
    assert "sub1.example.com" in result
    assert "sub2.example.com" in result
    assert "api.example.com" in result
    # Duplicate removed
    assert result.count("sub1.example.com") == 1


def test_httpx_parser_synthetic_jsonl():
    synthetic_jsonl = (
        '{"url":"https://app.example.com:443","input":"app.example.com","status_code":200,"title":"Dashboard","tech":["React","Nginx"],"chain":["https://example.com","https://app.example.com"]}\n'
        '{"url":"http://api.example.com","input":"api.example.com","status_code":401,"title":"Unauthorized","tech":["Express"]}\n'
    )
    services = parse_httpx_jsonl(synthetic_jsonl)
    assert len(services) == 2
    assert services[0].host == "app.example.com"
    assert services[0].status_code == 200
    assert "React" in services[0].technologies
    assert services[1].status_code == 401


def test_nmap_parser_synthetic_xml():
    synthetic_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="server.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.52"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
    hosts = parse_nmap_xml(synthetic_xml)
    assert len(hosts) == 1
    host = hosts[0]
    assert host.host == "server.example.com"
    assert host.ip == "192.168.1.10"
    assert len(host.ports) == 1
    assert host.ports[0].port == 80
    assert host.ports[0].service == "http"
    assert host.ports[0].product == "Apache httpd"
    assert host.ports[0].version == "2.4.52"


def test_nuclei_parser_synthetic_jsonl():
    synthetic_jsonl = (
        '{"template-id":"ssl-issuer","info":{"name":"SSL Certificate Issuer","severity":"info","description":"Reports issuer name","tags":["ssl","tls"]},"matched-at":"https://app.example.com"}\n'
        '{"template-id":"git-config-disclosure","info":{"name":"Git Config Exposure","severity":"medium","description":".git/config exposed"},"matched-at":"https://api.example.com/.git/config"}\n'
    )
    findings = parse_nuclei_jsonl(synthetic_jsonl)
    assert len(findings) == 2
    assert findings[0].template_id == "ssl-issuer"
    assert findings[0].severity == "info"
    assert findings[1].template_id == "git-config-disclosure"
    assert findings[1].severity == "medium"
    assert findings[1].to_dict()["verification_status"] == "tool-reported, unverified"
