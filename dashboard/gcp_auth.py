"""
gcp_auth.py - decide which GCP identity the dashboards authenticate as
=================================================================
google.cloud.bigquery.Client() picks credentials up from ambient state: the
GOOGLE_APPLICATION_CREDENTIALS environment variable first, then gcloud's
application-default credentials. A key exported in the shell for some other
project therefore wins silently, authenticates fine, and only fails later as
a 403 "does not have bigquery.jobs.create permission" on *this* project.

Two sources, trusted differently:

* A key named in the repo-root .env is deliberate, so it always wins - over
  whatever the shell exported, and even if it belongs to another project
  (cross-project access is legitimate when the roles have been granted).
* A key merely inherited from the environment is not deliberate. On a developer
  machine it is usually left over from unrelated work. It is used only if its
  project_id matches the project being queried, which is what keeps the Docker
  deployment working: compose.dashboard.yml mounts a key for this project and
  passes it by environment variable, and the image contains no .env at all.

describe() then reports the identity we actually ended up with, so the
synthetic-fallback banner can name it instead of showing a bare 403.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

VAR = "GOOGLE_APPLICATION_CREDENTIALS"


def apply(root: Path) -> str:
    """Settle which credentials are in play. Returns the identity in use."""
    configured = _configured_key(root)
    if configured:
        os.environ[VAR] = str(configured)
        return describe()

    dropped = _drop_foreign_key()
    if dropped:
        return f"{describe()} (ignoring {dropped})"
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


def _drop_foreign_key() -> str | None:
    """Unset an inherited key issued for a different project.

    Returns a description of what was dropped, or None if nothing was.
    """
    info = _key_info(os.environ.get(VAR))
    target = os.getenv("GCP_PROJECT_ID")
    if not info or not target:
        return None

    key_project = info.get("project_id")
    if not key_project or key_project == target:
        return None

    os.environ.pop(VAR, None)
    return (
        f"{info.get('client_email', 'unknown')}, a key for project "
        f"{key_project} rather than {target}; name it in .env to force it"
    )


def _key_info(path: str | None) -> dict | None:
    if not path or not os.path.exists(path):
        return None
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def describe() -> str:
    """Human-readable description of the credentials BigQuery will use."""
    path = os.environ.get(VAR)
    if not path:
        return "gcloud application-default credentials"
    if not os.path.exists(path):
        return f"a key file that does not exist ({path})"

    info = _key_info(path)
    if info is None:
        return f"an unreadable key file ({path})"

    described = "service account {} (from {})".format(
        info.get("client_email", "unknown"), path
    )
    key_project, target = info.get("project_id"), os.getenv("GCP_PROJECT_ID")
    if key_project and target and key_project != target:
        described += f", which belongs to project {key_project}, not {target}"
    return described


def hint(project: str) -> str:
    """What to do next when a read fails, tailored to the current identity."""
    if not os.environ.get(VAR):
        return (
            f"No usable {VAR} is set, so the gcloud application-default login is "
            f"being used. Put a key for {project} in keys/service-account.json "
            f"and add {VAR}=keys/service-account.json to the repo-root .env."
        )
    return (
        f"Check that this identity has the BigQuery Job User and Data Viewer "
        f"roles on {project}, or point {VAR} in the repo-root .env at a key "
        f"that does."
    )
