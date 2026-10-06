# Contributing

Use a feature branch and an English pull request. Squash merge after review and
validation; do not push directly to main. Keep personal paths and credentials
out of source, logs, issues, and artifacts.

Run python3 -m unittest discover -s tests -v and git diff --check.
Building or signing requires Python 3.12+, GnuPG, dpkg-dev and apt-utils.
Test keys are disposable. Production primary keys must remain offline.

Review every release registry change: version, immutable tag commit, manifest
SHA-256, Debian package SHA-256 and byte size. Never overwrite package bytes for
an existing version. Release entries are retained for previously installed clients.
