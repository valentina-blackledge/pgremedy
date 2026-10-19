"""scan never prints a password: not on success, not in errors."""

import json
from types import SimpleNamespace

import psycopg
import pytest
from click.testing import CliRunner

from pgremedy import scanner
from pgremedy.cli import cli
from pgremedy.errors import ConnectionFailed

SECRET = "Sup3rS3cretPW"


def run(*args, input=None):
    return CliRunner().invoke(cli, list(args), input=input)


@pytest.fixture
def fake_server(monkeypatch):
    """A 16.15 server; records the password scan was given."""
    seen = {}

    def read_server(conninfo, password=None):
        seen["password"] = password
        return scanner.ServerInfo("16.15", 160015, [], "scanner@db.example.com:5432/postgres")

    monkeypatch.setattr(scanner, "read_server", read_server)
    return seen


@pytest.mark.parametrize("conninfo", [
    f"postgresql://scanner:{SECRET}@db.example.com:5432/postgres",
    f"host=db.example.com port=5432 dbname=postgres user=scanner password={SECRET}",
    f"host=db.example.com user=scanner password='{SECRET} x'",
    f"postgresql://scanner@db.example.com/postgres?password={SECRET}",
])
@pytest.mark.parametrize("fmt", ["table", "json"])
def test_successful_scan_never_prints_the_password(world, fake_server, conninfo, fmt):
    result = run("scan", conninfo, "--format", fmt)
    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    assert "scanner@db.example.com:5432/postgres" in result.output
    assert "Tip: a password in the connection string" in " ".join(result.output.split())
    if fmt == "json":
        assert json.loads(result.stdout)["connection_info"] == "scanner@db.example.com:5432/postgres"


def test_no_tip_without_a_password_in_the_string(world, fake_server):
    result = run("scan", "service=prod")
    assert result.exit_code == 0, result.output
    assert "Tip:" not in result.output


def test_password_prompt(world, fake_server):
    result = run("scan", "postgresql://scanner@db.example.com/postgres", "-W", input=f"{SECRET}\n")
    assert result.exit_code == 0, result.output
    assert fake_server["password"] == SECRET
    assert SECRET not in result.output
    assert "Tip:" not in result.output


# Parse errors come from libpq itself, so these use its real messages.
@pytest.mark.parametrize("conninfo, leaked", [
    (f"postgresql://scanner:{SECRET}%ZZ@127.0.0.1/postgres", SECRET),            # bad %-escape: quotes the password
    (f"postgresql://scanner:{SECRET}@[::1/postgres", SECRET),                    # bad IPv6 host: quotes the whole URL
    (f"host=127.0.0.1 user=scanner password=Sup3r {SECRET}", SECRET),            # unquoted space: quotes the rest
])
def test_parse_errors_hide_what_libpq_quotes(conninfo, leaked):
    with pytest.raises(ConnectionFailed) as err:
        scanner.read_server(conninfo)
    message = str(err.value)
    assert message.startswith("the connection string couldn't be parsed")
    assert leaked not in message
    assert '"***"' in message


def test_parse_errors_keep_option_names():
    with pytest.raises(ConnectionFailed) as err:
        scanner.read_server(f"host=127.0.0.1 passwrd={SECRET}")
    assert str(err.value) == 'the connection string couldn\'t be parsed: invalid connection option "passwrd"'
    with pytest.raises(ConnectionFailed) as err:
        scanner.read_server("postgresql://scanner@127.0.0.1/postgres?sslmode")
    assert 'URI query parameter: "sslmode"' in str(err.value)


@pytest.mark.parametrize("conninfo, typed", [
    (f"postgresql://scanner:{SECRET}@db/postgres", SECRET),
    ("postgresql://scanner:p%40ssw0rd%21@db/postgres", "p%40ssw0rd%21"),   # percent-encoded as typed
])
def test_connection_errors_never_repeat_the_password(world, monkeypatch, conninfo, typed):
    decoded = psycopg.conninfo.conninfo_to_dict(conninfo)["password"]

    def echo(conninfo, **kwargs):
        raise psycopg.OperationalError(f'server said: bad password "{decoded}" (sent as {typed})')

    monkeypatch.setattr(psycopg, "connect", echo)
    result = run("scan", conninfo)
    assert result.exit_code == 2
    assert decoded not in result.output and typed not in result.output
    assert "couldn't connect to PostgreSQL" in " ".join(result.output.split())


def test_prompted_password_is_also_redacted(monkeypatch):
    def echo(conninfo, **kwargs):
        raise psycopg.OperationalError(f"rejected {kwargs['password']}")

    monkeypatch.setattr(psycopg, "connect", echo)
    with pytest.raises(ConnectionFailed) as err:
        scanner.read_server("postgresql://scanner@db/postgres", password=SECRET)
    assert str(err.value) == "rejected ***"


def test_connect_timeout_default(monkeypatch):
    calls = []

    def record(conninfo, **kwargs):
        calls.append(kwargs)
        raise psycopg.OperationalError("refused")

    monkeypatch.setattr(psycopg, "connect", record)
    for conninfo in ("postgresql://scanner@db/postgres", "postgresql://scanner@db/postgres?connect_timeout=3"):
        with pytest.raises(ConnectionFailed):
            scanner.read_server(conninfo)
    assert calls[0]["connect_timeout"] == scanner.DEFAULT_CONNECT_TIMEOUT
    assert "connect_timeout" not in calls[1]   # the user's own setting wins


def test_endpoint_description():
    info = SimpleNamespace(user="app", host="/var/run/postgresql", port=5432, dbname="orders", password=SECRET)
    assert scanner.describe_endpoint(info) == "app@/var/run/postgresql:5432/orders"
