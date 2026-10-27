import hashlib
import os
import subprocess
import tarfile
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).parents[1]


def _create_source_archive(tmp_path: Path, local_installer: str) -> Path:
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
    return archive


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
    archive = _create_source_archive(tmp_path, local_installer)
    install_dir = tmp_path / "local-install"
    environment = os.environ.copy()
    environment["CHXSEC_SOURCE_ARCHIVE_URL"] = archive.as_uri()
    environment["CHXSEC_SOURCE_ARCHIVE_SHA256"] = hashlib.sha256(
        archive.read_bytes()
    ).hexdigest()
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


@pytest.mark.parametrize(
    ("remote_installer", "local_installer"),
    [
        ("install-remote-fedora.sh", "install-fedora.sh"),
        ("install-remote-debian.sh", "install-debian.sh"),
    ],
)
def test_remote_installer_rejects_archive_with_wrong_checksum(
    tmp_path, remote_installer, local_installer
):
    archive = _create_source_archive(tmp_path, local_installer)
    actual_checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    wrong_checksum = ("0" if actual_checksum[0] != "0" else "1") + actual_checksum[1:]
    install_dir = tmp_path / "local-install"
    environment = os.environ.copy()
    environment["CHXSEC_SOURCE_ARCHIVE_URL"] = archive.as_uri()
    environment["CHXSEC_SOURCE_ARCHIVE_SHA256"] = wrong_checksum
    environment["CHXSEC_INSTALL_DIR"] = str(install_dir)

    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / remote_installer)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
    )

    assert result.returncode != 0
    assert "does not match CHXSEC_SOURCE_ARCHIVE_SHA256" in result.stderr
    assert not install_dir.exists()


@pytest.mark.parametrize(
    ("remote_installer", "local_installer"),
    [
        ("install-remote-fedora.sh", "install-fedora.sh"),
        ("install-remote-debian.sh", "install-debian.sh"),
    ],
)
@pytest.mark.parametrize(
    ("source_ref", "expected_url"),
    [
        (
            "v0.2.0",
            "https://github.com/chxchx-dev/chxchx-security/archive/refs/tags/v0.2.0.tar.gz",
        ),
        (
            "0123456789abcdef0123456789abcdef01234567",
            "https://github.com/chxchx-dev/chxchx-security/archive/0123456789abcdef0123456789abcdef01234567.tar.gz",
        ),
    ],
)
def test_remote_installer_downloads_pinned_tag_or_commit(
    tmp_path, remote_installer, local_installer, source_ref, expected_url
):
    archive = _create_source_archive(tmp_path, local_installer)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl_stub = bin_dir / "curl"
    curl_stub.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import shutil\n"
        "import sys\n"
        "arguments = sys.argv[1:]\n"
        "with open(os.environ['CHXSEC_CURL_CAPTURE'], 'w', encoding='utf-8') as capture:\n"
        "    capture.write(arguments[arguments.index('--output') - 1])\n"
        "shutil.copyfile(os.environ['CHXSEC_TEST_ARCHIVE'], "
        "arguments[arguments.index('--output') + 1])\n",
        encoding="utf-8",
    )
    curl_stub.chmod(0o755)

    install_dir = tmp_path / "local-install"
    capture_path = tmp_path / "curl-url.txt"
    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment.get('PATH', '')}"
    environment["CHXSEC_SOURCE_REF"] = source_ref
    environment["CHXSEC_SOURCE_ARCHIVE_SHA256"] = hashlib.sha256(
        archive.read_bytes()
    ).hexdigest()
    environment["CHXSEC_TEST_ARCHIVE"] = str(archive)
    environment["CHXSEC_CURL_CAPTURE"] = str(capture_path)
    environment["CHXSEC_INSTALL_DIR"] = str(install_dir)

    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / remote_installer), "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert capture_path.read_text(encoding="utf-8") == expected_url
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
