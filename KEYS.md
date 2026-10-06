# Signing key ceremony

The primary certification key is kept offline. APT metadata and bundle manifests
use different Ed25519 signing subkeys. The APT workflow receives only its own
encrypted secret subkey and passphrase, in the release-signing environment.

## Create keys on the offline machine

Requires Python 3.12+ and GnuPG 2.4. Copy this reviewed repository to the offline
machine and disconnect it from networks. Choose a new directory on encrypted
offline storage, outside this repository.

Run: python3 scripts/create-keys.py --output /path/to/new/offline-directory

The passphrase is entered locally without echo; do not send it in chat. The
script creates a certification-only primary key (five years) and two signing
subkeys (one year). Back up the complete output directory on separate encrypted
offline storage before using the keys.

Keep gnupg/, primary-secret.asc and the revocation certificate offline. Transfer
only the online/ directory, containing the public key, public fingerprints and
the encrypted APT and bundle subkeys. The primary secret must never enter GitHub,
Actions, logs, build caches, or online keyrings.

## Register the APT subkey online

Review online/fingerprints.json against the offline record. Import only the public
key into keys/mognitio.asc through a pull request and populate the three public
fingerprints in repository.json. No secret file is committed.

On an online machine authenticated as a repository administrator, run:
python3 scripts/register-apt-key.py /path/to/online

This validates that the APT file contains a stub primary and exactly the selected
APT subkey, then stores APT_SIGNING_KEY and APT_SIGNING_PASSPHRASE in the
release-signing GitHub environment. The passphrase is read locally without echo.
Only the APT subkey is registered here. Bundle signing setup belongs to the
Mognitio release pipeline.

Delete the transferred encrypted subkey files from online working directories
after confirming that the environment secrets are registered. Retain offline
backups. Do not erase the primary backup or revocation material.

## Renewal and incidents

Renew subkeys before their one-year expiry using the offline primary, update
public key material and reviewed fingerprints, and replace only the corresponding
environment secret. Publish the updated keyring and fingerprint record.

For compromise, stop the signing workflow, remove the affected secret, revoke
the affected subkey using the offline primary, and publish updated trust
information before resuming. A compromised GitHub account is not an independent
authority for its own replacement key; the current trust policy and its limits
are documented in OPERATIONS.md.
