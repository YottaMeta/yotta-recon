#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yotta-recon 测试套件（零依赖 unittest，Python 3.8+）。

覆盖：端口/目标解析、Scope Guard 授权纪律、真实本地服务指纹（HTTP/SSH/FTP/
Redis/SMTP banner）、风险评估、JSON/Markdown 输出、CLI 退出码。
运行：python scripts/test_yotta_recon.py
"""

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import yotta_recon as yr

PY = sys.executable
ENGINE = os.path.join(HERE, "yotta_recon.py")


# ---------------------------------------------------------------------------
# 测试用本地服务
# ---------------------------------------------------------------------------

class BannerServer(threading.Thread):
    """连接后发送固定 banner 的 TCP 服务。"""

    def __init__(self, banner):
        super().__init__(daemon=True)
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.sendall(self.banner)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class EchoServer(threading.Thread):
    """简单 echo 服务（无 banner），用于纯端口开放探测。"""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.sendall(b"hello\r\n")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class HttpBannerServer(threading.Thread):
    """返回自定义 Server 头的 HTTP 服务。"""

    def __init__(self, server_header):
        super().__init__(daemon=True)
        self.server_header = server_header
        self.httpd = None
        self.port = None

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Server", server_header)
                self.end_headers()
                self.wfile.write(b"<html><body>ok</body></html>")

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]

    def run(self):
        self.httpd.serve_forever(poll_interval=0.05)

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 端口 / 目标解析
# ---------------------------------------------------------------------------

class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(yr.parse_ports("22"), [22])

    def test_multi(self):
        self.assertEqual(yr.parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(yr.parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_mixed(self):
        self.assertEqual(yr.parse_ports("80,443,8000-8002"),
                         [80, 443, 8000, 8001, 8002])

    def test_top_default(self):
        ports = yr.parse_ports("top")
        self.assertEqual(len(ports), 100)
        self.assertEqual(ports[0], 20)
        self.assertEqual(ports[-1], ports[-1])  # 仅验证数量与起点

    def test_top_n(self):
        ports = yr.parse_ports("top:5")
        self.assertEqual(ports, [20, 21, 22, 23, 25])

    def test_invalid(self):
        with self.assertRaises(ValueError):
            yr.parse_ports("22,abc")
        with self.assertRaises(ValueError):
            yr.parse_ports("99999")
        with self.assertRaises(ValueError):
            yr.parse_ports("10-1")

    def test_dedup(self):
        self.assertEqual(yr.parse_ports("22,22,23"), [22, 23])


class TestParseTargets(unittest.TestCase):
    def test_single_ip(self):
        hosts, src = yr.parse_targets("127.0.0.1")
        self.assertEqual(hosts, ["127.0.0.1"])

    def test_multi(self):
        hosts, _ = yr.parse_targets("127.0.0.1,127.0.0.2")
        self.assertEqual(hosts, ["127.0.0.1", "127.0.0.2"])

    def test_cidr(self):
        hosts, _ = yr.parse_targets("127.0.0.0/30")
        self.assertEqual(hosts, ["127.0.0.1", "127.0.0.2"])

    def test_cidr24_count(self):
        hosts, _ = yr.parse_targets("192.168.1.0/24")
        self.assertEqual(len(hosts), 254)

    def test_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as fh:
            fh.write("# comment\n127.0.0.1\n127.0.0.0/30\n")
            path = fh.name
        try:
            hosts, src = yr.parse_targets(None, path)
            self.assertEqual(hosts, ["127.0.0.1", "127.0.0.2"])  # /30 展开 2 台 + 去重
            self.assertIn("file:", src)
        finally:
            os.unlink(path)

    def test_empty(self):
        with self.assertRaises(ValueError):
            yr.parse_targets("")


# ---------------------------------------------------------------------------
# Scope Guard
# ---------------------------------------------------------------------------

class TestScopeGuard(unittest.TestCase):
    def test_classify_ip(self):
        self.assertEqual(yr.classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(yr.classify_ip("::1"), "loopback")
        self.assertEqual(yr.classify_ip("192.168.1.1"), "private")
        self.assertEqual(yr.classify_ip("10.0.0.1"), "private")
        self.assertEqual(yr.classify_ip("8.8.8.8"), "public")
        self.assertEqual(yr.classify_ip("169.254.1.1"), "link_local")
        self.assertEqual(yr.classify_ip("224.0.0.1"), "multicast")

    def test_loopback_allowed_by_default(self):
        g = yr.ScopeGuard()
        ok, _ = g.check_host("127.0.0.1")
        self.assertTrue(ok)
        ok, _ = g.check_host("localhost")
        self.assertTrue(ok)

    def test_public_denied_by_default(self):
        g = yr.ScopeGuard()
        ok, reason = g.check_host("8.8.8.8")
        self.assertFalse(ok)
        self.assertIn("不在授权范围", reason)

    def test_private_denied_by_default(self):
        g = yr.ScopeGuard()
        ok, _ = g.check_host("192.168.1.1")
        self.assertFalse(ok)

    def test_scope_file_allow(self):
        with tempfile.NamedTemporaryFile("w", suffix=".scope", delete=False,
                                         encoding="utf-8") as fh:
            fh.write("# scope\n192.168.1.0/24\n10.0.0.5\n")
            path = fh.name
        try:
            g = yr.ScopeGuard(scope_file=path)
            self.assertTrue(g.check_host("192.168.1.99")[0])
            self.assertTrue(g.check_host("10.0.0.5")[0])
            self.assertFalse(g.check_host("10.0.0.6")[0])
            self.assertFalse(g.check_host("8.8.8.8")[0])
        finally:
            os.unlink(path)

    def test_assume_authorized(self):
        g = yr.ScopeGuard(assume_authorized=True)
        ok, _ = g.check_host("8.8.8.8")
        self.assertTrue(ok)

    def test_hostname_in_scope(self):
        with tempfile.NamedTemporaryFile("w", suffix=".scope", delete=False,
                                         encoding="utf-8") as fh:
            fh.write("example.test\n")
            path = fh.name
        try:
            g = yr.ScopeGuard(scope_file=path)
            ok, reason = g.check_host("example.test")
            self.assertTrue(ok)
            self.assertIn("scope-host", reason)
        finally:
            os.unlink(path)

    def test_partition(self):
        g = yr.ScopeGuard()
        allowed, denied = g.partition(["127.0.0.1", "8.8.8.8"])
        self.assertEqual(allowed, ["127.0.0.1"])
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0][0], "8.8.8.8")
        self.assertIn("不在授权范围", denied[0][1])

    def test_confirm_noninteractive_denies(self):
        g = yr.ScopeGuard()
        allowed, denied = g.confirm_or_partition(["8.8.8.8"], interactive=False)
        self.assertEqual(allowed, [])
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0][0], "8.8.8.8")

    def test_scope_file_missing(self):
        with self.assertRaises(ValueError):
            yr.ScopeGuard(scope_file="no_such_file.scope")


# ---------------------------------------------------------------------------
# 指纹识别（单元级）
# ---------------------------------------------------------------------------

class TestIdentify(unittest.TestCase):
    def test_http_server_header(self):
        prod, ver = yr.identify_service(
            80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\n\r\n")
        self.assertEqual(prod, "apache")
        self.assertEqual(ver, "2.4.7")

    def test_nginx(self):
        prod, ver = yr.identify_service(
            8080, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
        self.assertEqual(prod, "nginx")
        self.assertEqual(ver, "1.18.0")

    def test_ssh(self):
        prod, ver = yr.identify_service(
            22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        self.assertEqual(prod, "openssh")
        self.assertEqual(ver, "8.9")

    def test_proftpd(self):
        prod, ver = yr.identify_service(
            21, "220 ProFTPD 1.3.5e Server (Debian) [::ffff:127.0.0.1]\r\n")
        self.assertEqual(prod, "proftpd")
        self.assertEqual(ver, "1.3.5")

    def test_vsftpd(self):
        prod, ver = yr.identify_service(21, "220 (vsFTPd 2.3.4)\r\n")
        self.assertEqual(prod, "vsftpd")
        self.assertEqual(ver, "2.3.4")

    def test_smtp_postfix(self):
        prod, ver = yr.identify_service(
            25, "220 mail.example.com ESMTP Postfix\r\n")
        self.assertEqual(prod, "postfix")
        self.assertIsNone(ver)

    def test_pop3(self):
        prod, _ = yr.identify_service(110, "+OK Dovecot ready.\r\n")
        self.assertEqual(prod, "dovecot-pop3")

    def test_imap(self):
        prod, _ = yr.identify_service(143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n")
        self.assertEqual(prod, "dovecot-imap")

    def test_redis(self):
        prod, _ = yr.identify_service(6379, "+PONG\r\n")
        self.assertEqual(prod, "redis")

    def test_mysql_handshake(self):
        # 握手包：0x0a + 版本号 + \x00 ...
        hello = bytes.fromhex("0a352e372e333300010203").decode("latin-1")
        prod, ver = yr.identify_service(3306, hello)
        self.assertEqual(prod, "mysql")
        self.assertEqual(ver, "5.7.33")

    def test_tls(self):
        hello = bytes.fromhex("160301002c0100").decode("latin-1")
        prod, _ = yr.identify_service(443, hello)
        self.assertEqual(prod, "tls")

    def test_unknown(self):
        prod, ver = yr.identify_service(31337, "random data here")
        self.assertIsNone(prod)


class TestRisk(unittest.TestCase):
    def test_known_high(self):
        sev, note = yr.assess_risk("proftpd", "1.3.5")
        self.assertEqual(sev, 3)
        self.assertIn("CVE-2015-3306", note)

    def test_known_medium(self):
        sev, _ = yr.assess_risk("openssh", "5.9")
        self.assertEqual(sev, 2)

    def test_known_low(self):
        sev, _ = yr.assess_risk("apache", "2.4.7")
        self.assertEqual(sev, 1)

    def test_unknown_none(self):
        sev, note = yr.assess_risk("nginx", "1.18.0")
        self.assertEqual(sev, 0)
        self.assertIsNone(note)

    def test_missing_version(self):
        sev, _ = yr.assess_risk("proftpd", None)
        self.assertEqual(sev, 0)


# ---------------------------------------------------------------------------
# 真实本地服务扫描 / 指纹
# ---------------------------------------------------------------------------

class TestScanLocal(unittest.TestCase):
    def test_scan_finds_open_port(self):
        srv = EchoServer()
        srv.start()
        try:
            res = yr.scan_target("127.0.0.1", [srv.port, 1, 2],
                                 timeout=0.5, concurrency=8, probe=False)
            ports = [e["port"] for e in res["ports"]]
            self.assertIn(srv.port, ports)
            self.assertEqual(res["port_count"], 1)
        finally:
            srv.stop()

    def test_http_fingerprint(self):
        srv = HttpBannerServer("Apache/2.4.7 (Ubuntu)")
        srv.start()
        try:
            fp = yr.probe_service("127.0.0.1", srv.port, timeout=1.0)
            self.assertEqual(fp["product"], "apache")
            self.assertEqual(fp["version"], "2.4.7")
        finally:
            srv.stop()

    def test_ssh_banner(self):
        srv = BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        srv.start()
        try:
            fp = yr.probe_service("127.0.0.1", srv.port, timeout=1.0)
            self.assertEqual(fp["product"], "openssh")
            self.assertEqual(fp["version"], "8.9")
        finally:
            srv.stop()

    def test_ftp_banner_and_risk(self):
        srv = BannerServer(b"220 ProFTPD 1.3.5e Server (Debian)\r\n")
        srv.start()
        try:
            fp = yr.probe_service("127.0.0.1", srv.port, timeout=1.0)
            self.assertEqual(fp["product"], "proftpd")
            self.assertEqual(fp["version"], "1.3.5")
            sev, note = yr.assess_risk(fp["product"], fp["version"])
            self.assertEqual(sev, 3)
            self.assertIsNotNone(note)
        finally:
            srv.stop()

    def test_redis_probe(self):
        srv = BannerServer(b"+PONG\r\n")
        srv.start()
        try:
            fp = yr.probe_service("127.0.0.1", srv.port, timeout=1.0)
            self.assertEqual(fp["product"], "redis")
        finally:
            srv.stop()

    def test_smtp_probe(self):
        srv = BannerServer(b"220 mail.example.com ESMTP Postfix\r\n")
        srv.start()
        try:
            fp = yr.probe_service("127.0.0.1", srv.port, timeout=1.0)
            self.assertEqual(fp["product"], "postfix")
        finally:
            srv.stop()

    def test_full_scan_with_probe(self):
        srv = BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        srv.start()
        try:
            res = yr.scan_target("127.0.0.1", [srv.port], timeout=0.8,
                                 concurrency=4, probe=True)
            self.assertEqual(res["port_count"], 1)
            e = res["ports"][0]
            self.assertEqual(e["product"], "openssh")
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

class TestOutput(unittest.TestCase):
    def test_json_schema(self):
        meta = {"generated_at": "t", "scan_id": "s1",
                "authorization": "loopback"}
        results = [{"host": "127.0.0.1", "ports": [], "duration_ms": 1,
                    "port_count": 0}]
        data = yr.build_json(meta, results, [("8.8.8.8", "denied")])
        self.assertEqual(data["tool"], "yotta-recon")
        self.assertEqual(data["scan_id"], "s1")
        self.assertEqual(data["summary"]["denied_targets"], 1)

    def test_write_report(self):
        meta = {"generated_at": "2026-08-26 12:00:00 CST",
                "scan_id": "s1", "authorization": "loopback"}
        results = [{"host": "127.0.0.1",
                    "ports": [{"port": 22, "state": "open", "service": "ssh",
                               "product": "openssh", "version": "8.9",
                               "risk_label": "none", "note": None}],
                    "port_count": 1}]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.md")
            yr.write_report(path, meta, results, [])
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("# 元析 侦察报告", text)
            self.assertIn("| 22 |", text)
            self.assertIn("openssh", text)
            self.assertIn("《网络安全法》", text)

    def test_format_text(self):
        results = [{"host": "127.0.0.1", "ports": [
            {"port": 22, "product": "openssh", "version": "8.9"}], "port_count": 1}]
        text = yr.format_text(results, [])
        self.assertIn("## 127.0.0.1", text)
        self.assertIn("openssh", text)


# ---------------------------------------------------------------------------
# CLI 集成（子进程）
# ---------------------------------------------------------------------------

class TestCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([PY, ENGINE] + list(args), capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=60)

    def test_version(self):
        r = self._run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("yotta-recon 0.1.5", r.stdout)

    def test_list_ports(self):
        r = self._run("list-ports")
        self.assertEqual(r.returncode, 0)
        self.assertIn("ssh", r.stdout)

    def test_check_scope_loopback(self):
        r = self._run("check-scope", "--targets", "127.0.0.1")
        self.assertEqual(r.returncode, 0)
        self.assertIn("ALLOW", r.stdout)

    def test_check_scope_public_denied(self):
        r = self._run("check-scope", "--targets", "8.8.8.8")
        self.assertEqual(r.returncode, 3)
        self.assertIn("DENY", r.stdout)

    def test_check_scope_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".scope", delete=False,
                                         encoding="utf-8") as fh:
            fh.write("10.0.0.0/8\n")
            path = fh.name
        try:
            r = self._run("check-scope", "--targets", "10.1.2.3", "--scope", path)
            self.assertEqual(r.returncode, 0)
            self.assertIn("ALLOW", r.stdout)
        finally:
            os.unlink(path)

    def test_scan_public_denied_noninteractive(self):
        r = self._run("scan", "--targets", "8.8.8.8", "--no-interactive",
                      "--ports", "80", "--no-probe")
        self.assertEqual(r.returncode, 3)
        self.assertIn("拒绝", r.stderr)

    def test_scan_loopback_json(self):
        srv = BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        srv.start()
        try:
            r = self._run("scan", "--targets", "127.0.0.1",
                          "--ports", str(srv.port), "--json")
            if r.returncode != 0 or not r.stdout:
                print("DIAG rc=%r out=%r err=%r" % (r.returncode, r.stdout[:200], r.stderr[:300]))
            self.assertEqual(r.returncode, 0)
            data = json.loads(r.stdout)
            self.assertEqual(data["summary"]["open_ports"], 1)
            self.assertEqual(data["results"][0]["ports"][0]["product"],
                             "openssh")
        finally:
            srv.stop()

    def test_scan_markdown_report(self):
        srv = EchoServer()
        srv.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "report.md")
                r = self._run("scan", "--targets", "127.0.0.1",
                              "--ports", str(srv.port), "--no-probe",
                              "--report", out)
                self.assertEqual(r.returncode, 0)
                self.assertTrue(os.path.exists(out))
                with open(out, "r", encoding="utf-8") as fh:
                    self.assertIn("侦察报告", fh.read())
        finally:
            srv.stop()

    def test_fingerprint_cmd(self):
        srv = BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        srv.start()
        try:
            r = self._run("fingerprint", "--host", "127.0.0.1",
                          "--port", str(srv.port))
            self.assertEqual(r.returncode, 0)
            self.assertIn("openssh", r.stdout)
        finally:
            srv.stop()

    def test_local_cmd(self):
        r = self._run("local")
        self.assertEqual(r.returncode, 0)


def main():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
