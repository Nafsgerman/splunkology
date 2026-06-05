"""README hero structure validation (Splunk-era)."""

from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"


def _read() -> str:
    return README.read_text(encoding="utf-8")


def test_readme_exists() -> None:
    assert README.exists(), "README.md missing at repo root"


def test_h1_is_splunkology() -> None:
    first = _read().splitlines()[0].strip()
    assert first == "# Splunkology", f"unexpected H1: {first!r}"


def test_embeds_at_least_one_figure() -> None:
    text = _read()
    assert (
        "](architecture_diagram.png)" in text
        or "](docs/figures/" in text
        or "](docs/architecture/" in text
    ), "README must embed the architecture diagram"
