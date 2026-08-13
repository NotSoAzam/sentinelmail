"""
SentinelMail CLI.

Usage:
    sentinelmail lookup you@example.com
    sentinelmail lookup you@example.com --json
    sentinelmail lookup you@example.com --output report.json
"""
from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinelmail.engine import run_investigation
from sentinelmail.models import Category, Confidence
from sentinelmail.risk import risk_label, score_investigation
from sentinelmail.validation import InvalidEmailError

console = Console()

CONFIDENCE_STYLE = {
    Confidence.VERIFIED: "bold green",
    Confidence.HIGH: "green",
    Confidence.MEDIUM: "yellow",
    Confidence.LOW: "orange3",
    Confidence.UNVERIFIED: "grey58",
}


@click.group()
@click.version_option()
def main():
    """SentinelMail — evidence-driven email security intelligence for authorized investigations."""


@main.command()
@click.argument("email")
@click.option("--json", "as_json", is_flag=True, help="Print raw JSON instead of a formatted report.")
@click.option("--output", "output_path", type=click.Path(), help="Write the JSON report to this file.")
def lookup(email: str, as_json: bool, output_path: str | None):
    """Investigate a single email address using legitimate public sources."""
    try:
        if not as_json:
            console.print(f"[bold cyan]SentinelMail[/bold cyan] investigating [bold]{email}[/bold]\n")

        def on_progress(provider_name: str, status: str):
            if not as_json:
                console.print(f"  [dim]{provider_name:<12}[/dim] {status}")

        result = run_investigation(email, progress_callback=None if as_json else on_progress)

    except InvalidEmailError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    score, contributions = score_investigation(result)

    if as_json or output_path:
        payload = result.to_dict()
        payload["risk"] = {
            "score": score,
            "label": risk_label(score),
            "contributions": [{"reason": c.reason, "points": c.points} for c in contributions],
        }
        rendered = json.dumps(payload, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(rendered)
            console.print(f"[green]Report written to {output_path}[/green]")
        if as_json:
            print(rendered)
        return

    _print_report(result, score, contributions)


def _print_report(result, score, contributions):
    console.print()
    console.print(Panel.fit(
        f"[bold]{result.email}[/bold]\nDomain: {result.domain}",
        title="Investigation Summary", border_style="cyan",
    ))

    for category in Category:
        findings = result.by_category(category)
        if not findings:
            continue
        table = Table(title=category.value.replace("_", " ").title(), show_lines=False, expand=True)
        table.add_column("Confidence", width=12)
        table.add_column("Finding")
        table.add_column("Source", style="dim")
        for f in findings:
            style = CONFIDENCE_STYLE.get(f.confidence, "")
            table.add_row(f"[{style}]{f.confidence.value}[/{style}]", f.description, f.source)
        console.print(table)

    console.print()
    risk_style = {
        "Very Low": "green", "Low": "green", "Moderate": "yellow",
        "High": "red", "Critical": "bold red",
    }.get(risk_label(score), "white")
    console.print(Panel.fit(
        f"[bold {risk_style}]{score}/100 — {risk_label(score)}[/bold {risk_style}]\n\n"
        + ("\n".join(f"  • {c.reason} (+{c.points})" for c in contributions) if contributions
           else "  No risk-elevating signals found."),
        title="Risk Score", border_style=risk_style,
    ))

    if result.errors:
        console.print()
        console.print("[yellow]Provider warnings:[/yellow]")
        for err in result.errors:
            console.print(f"  [dim]{err}[/dim]")

    console.print()
    console.print("[dim]Findings marked UNVERIFIED could not be checked (e.g. missing API key) — "
                   "they are not evidence of anything, positive or negative.[/dim]")


@main.command()
def providers():
    """List available providers and whether they're active."""
    from sentinelmail.providers import ALL_PROVIDERS
    table = Table(title="SentinelMail Providers")
    table.add_column("Name")
    table.add_column("Requires API Key")
    table.add_column("Status")
    for provider_cls in ALL_PROVIDERS:
        p = provider_cls()
        status = "[green]ready[/green]" if p.is_available() else "[yellow]needs config[/yellow]"
        table.add_row(p.name, "yes" if p.requires_api_key else "no", status)
    console.print(table)


if __name__ == "__main__":
    main()
