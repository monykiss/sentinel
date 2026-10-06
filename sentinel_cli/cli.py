"""SENTINEL CLI — command-line interface for SENTINEL security monitoring."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Any

CONFIG_FILE = pathlib.Path("~/.sentinel/config.json").expanduser()

#: The key is read from the environment by default so it never has to appear
#: on a command line, where it would land in shell history and `ps` output.
API_KEY_ENV = "SENTINEL_API_KEY"


def _load_config() -> dict[str, str]:
    """Load CLI config from ~/.sentinel/config.json."""
    if not CONFIG_FILE.exists():
        print(f"No config found. Run: {API_KEY_ENV}=<KEY> sentinel init --gateway <URL>")
        sys.exit(1)
    return json.loads(CONFIG_FILE.read_text())


def _write_private(path: pathlib.Path, text: str) -> None:
    """Write a file only its owner can read. It holds a bearer credential."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    # O_CREAT's mode does not apply to a file that already existed.
    os.chmod(path, 0o600)


def _api_get(path: str, config: dict) -> dict[str, Any]:
    """GET request to SENTINEL gateway."""
    import requests

    url = f"{config['gateway_url'].rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {config['api_key']}"}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _api_post(path: str, config: dict, data: dict | None = None) -> dict[str, Any]:
    """POST request to SENTINEL gateway."""
    import requests

    url = f"{config['gateway_url'].rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {config['api_key']}"}
    resp = requests.post(url, headers=headers, json=data or {}, timeout=10)
    resp.raise_for_status()
    return resp.json()


# ── Commands ──


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize CLI configuration."""
    api_key = args.api_key or os.environ.get(API_KEY_ENV)
    if not api_key:
        print(f"No API key. Set {API_KEY_ENV} (preferred) or pass --api-key.")
        sys.exit(1)
    config = {
        "api_key": api_key,
        "gateway_url": args.gateway,
    }
    _write_private(CONFIG_FILE, json.dumps(config, indent=2))
    print(f"Config written to {CONFIG_FILE} (mode 600)")

    # Test connection
    try:
        import requests

        resp = requests.get(f"{args.gateway.rstrip('/')}/healthz", timeout=5)
        if resp.status_code == 200:
            print(f"Connected to SENTINEL gateway at {args.gateway}")
        else:
            print(f"Warning: gateway returned {resp.status_code}")
    except Exception as e:
        print(f"Warning: could not connect to gateway — {e}")


def cmd_status(args: argparse.Namespace) -> None:
    """Show agent dashboard status."""
    config = _load_config()
    data = _api_get("/v1/agents/dashboard", config)

    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print(
            f"\n[bold]SENTINEL Dashboard[/bold]  |  "
            f"Agents: [cyan]{data['agent_count']}[/cyan]  |  "
            f"Events: [cyan]{data['total_events']}[/cyan]  |  "
            f"Hard Wall: [{'red' if data['hard_wall_active'] else 'green'}]"
            f"{'ACTIVE' if data['hard_wall_active'] else 'OFF'}[/]"
        )

        if data.get("events_by_severity"):
            table = Table(title="Events by Severity")
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="right")
            sev_labels = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFO"}
            sev_colors = {0: "red", 1: "yellow", 2: "cyan", 3: "blue", 4: "dim"}
            for sev, count in sorted(data["events_by_severity"].items()):
                s = int(sev)
                table.add_row(
                    f"[{sev_colors.get(s, 'white')}]{sev_labels.get(s, sev)}[/]",
                    str(count),
                )
            console.print(table)
    except ImportError:
        # Fallback without rich
        print(json.dumps(data, indent=2))


def cmd_events(args: argparse.Namespace) -> None:
    """Show recent security events."""
    config = _load_config()
    path = "/v1/agents/status"
    data = _api_get(path, config)
    events = data.get("events", data.get("recent_critical", []))

    if not events:
        print("No events found.")
        return

    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title=f"Recent Events (limit {args.limit})")
        table.add_column("Severity", width=10)
        table.add_column("Agent", width=10)
        table.add_column("Type", width=20)
        table.add_column("Description")

        for e in events[: args.limit]:
            sev = e.get("severity", "?")
            table.add_row(str(sev), e.get("source_agent", "?"), e.get("event_type", "?"), e.get("description", ""))
        console.print(table)
    except ImportError:
        for e in events[: args.limit]:
            print(f"[SEV {e.get('severity')}] {e.get('source_agent')}: {e.get('description')}")


def cmd_machines(args: argparse.Namespace) -> None:
    """List registered machines."""
    config = _load_config()
    data = _api_get("/v1/agents/dashboard", config)

    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Registered Machines")
        table.add_column("Agent ID")
        table.add_column("Status")
        table.add_column("Registered At")

        agents = data.get("registered_agents", {})
        if isinstance(agents, dict):
            for key, info in agents.items():
                table.add_row(
                    info.get("agent_id", key),
                    info.get("status", "unknown"),
                    info.get("registered_at", "?"),
                )
        console.print(table)
    except ImportError:
        print(json.dumps(data.get("registered_agents", {}), indent=2))


def cmd_scan(args: argparse.Namespace) -> None:
    """Trigger an immediate scan."""
    config = _load_config()
    data = _api_post(
        "/v1/agents/events",
        config,
        {
            "severity": 4,
            "event_type": "MANUAL_SCAN",
            "source_agent": "CLI",
            "description": "Manual scan triggered via sentinel-cli",
        },
    )
    print(f"Scan triggered. Event ID: {data.get('id', 'unknown')}")
    print("Results appear in: sentinel events")


# ── Main ──


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL Security Monitoring CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # init
    p_init = sub.add_parser("init", help="Initialize CLI configuration")
    p_init.add_argument("--api-key", help=f"SENTINEL API key (prefer the {API_KEY_ENV} environment variable)")
    p_init.add_argument("--gateway", required=True, help="Gateway URL, e.g. https://sentinel.example.com")

    # status
    sub.add_parser("status", help="Show agent dashboard")

    # events
    p_events = sub.add_parser("events", help="Show recent events")
    p_events.add_argument("--limit", type=int, default=20, help="Max events to show")

    # machines
    sub.add_parser("machines", help="List registered machines")

    # scan
    sub.add_parser("scan", help="Trigger immediate scan")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "init": cmd_init,
        "status": cmd_status,
        "events": cmd_events,
        "machines": cmd_machines,
        "scan": cmd_scan,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
