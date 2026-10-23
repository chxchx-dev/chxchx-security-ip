import os
import subprocess
import tarfile
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    ("remote_installer", "local_installer"),
    [
        ("install-remote-fedora.sh", "install-fedora.sh"),
        ("install-remote-debian.sh", "install-debian.sh"),
    ],
)
def test_remote_installer_extracts_source_and_forwards_arguments(
    tmp_path, remote_installer, local_installer
):
    source_root = tmp_path / "source" / "repo"
    source_root.mkdir(parents=True)
    installer = source_root / local_installer
    installer.write_text(
        '#!/usr/bin/env bash\nprintf \'<%s>\\n\' "$@"\n',
        encoding="utf-8",
    )
    installer.chmod(0o755)

    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(installer, arcname=f"repository/{local_installer}")

    install_dir = tmp_path / "local-install"
    environment = os.environ.copy()
    environment["CHXSEC_SOURCE_ARCHIVE_URL"] = archive.as_uri()
    environment["CHXSEC_INSTALL_DIR"] = str(install_dir)

    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / remote_installer), "--dry-run", "--with-dev"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-2:] == ["<--dry-run>", "<--with-dev>"]
    assert (install_dir / local_installer).is_file()


def test_apt_installer_help_lists_supported_options():
    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / "install-debian.sh"), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "Ubuntu or Kali Linux" in result.stdout
    assert "--dry-run" in result.stdout
    assert "--no-system-packages" in result.stdout
