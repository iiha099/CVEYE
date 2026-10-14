"""
gcp_auth.py - decide which GCP identity the dashboards authenticate as
=================================================================
google.cloud.bigquery.Client() picks credentials up from ambient state: the
GOOGLE_APPLICATION_CREDENTIALS environment variable first, then gcloud's
application-default credentials. A key exported in the shell for some other
project therefore wins silently, authenticates fine, and only fails later as
a 403 "does not have bigquery.jobs.create permission" on *this* project.

So the repo's own .env is treated as authoritative: if it names a key file we
use that one, even when the shell already exported a different path
(python-dotenv's load_dotenv deliberately does not overwrite existing
variables). describe() then reports the identity we actually ended up with, so
the synthetic-fallback banner can name it instead of showing a bare 403.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

VAR = "GOOGLE_APPLICATION_CREDENTIALS"


def apply(root: Path) -> str:
    """Make <root>/.env the only source for VAR. Returns the identity in use.

    If .env names a key we use it, overriding whatever the shell exported. If
    .env names none we *clear* any inherited value rather than falling through
    to it, so a key exported for an unrelated project can never be used to read
    this one.
    """
    configured = _configured_key(root)
    if configured:
        os.environ[VAR] = str(configured)
    else:
        os.environ.pop(VAR, None)
    return describe()


def _configured_key(root: Path) -> Path | None:
    """The key path set in .env, resolved relative to the repo root."""
    try:
        from dotenv import dotenv_values
    except ImportError:
        return None

    value = (dotenv_values(root / ".env").get(VAR) or "").strip()
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def describe() -> str:
    """Human-readable description of the credentials BigQuery will use."""
    path = os.environ.get(VAR)
    if not path:
        return "gcloud application-default credentials"
    if not os.path.exists(path):
        return f"a key file that does not exist ({path})"
    try:
        info = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return f"an unreadable key file ({path})"
    return "service account {} (project {}, from {})".format(
        info.get("client_email", "unknown"),
        info.get("project_id", "unknown"),
        path,
    )


def hint(project: str) -> str:
    """What to do next when a read fails, tailored to the current identity."""
    if not os.environ.get(VAR):
        return (
            f"No {VAR} is set, so the gcloud application-default login is being "
            f"used. Put a key for {project} in keys/service-account.json and add "
            f"{VAR}=keys/service-account.json to the repo-root .env."
        )
    return (
        f"Check that this identity has the BigQuery Job User and Data Viewer "
        f"roles on {project}, or point {VAR} in the repo-root .env at a key "
        f"that does."
    )
