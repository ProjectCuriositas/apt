#!/usr/bin/env python3
"""Interactive key ceremony; run on the owner's offline machine only."""
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess

def main(output):
    if output.exists():
        raise ValueError("Choose a new directory on encrypted offline storage")
    password=getpass.getpass("New key passphrase (not sent anywhere): ")
    if len(password)<12 or password!=getpass.getpass("Repeat passphrase: "):
        raise ValueError("Use a matching passphrase of at least 12 characters")
    os.umask(0o077)
    output.mkdir(parents=True,mode=0o700)
    home=output/"gnupg";home.mkdir(mode=0o700)
    online=output/"online";online.mkdir(mode=0o700)
    env=dict(os.environ,GNUPGHOME=str(home.resolve()))
    def gpg(*args):
        return subprocess.run(["gpg","--batch","--pinentry-mode","loopback","--passphrase-fd","0",*args],
            input=(password+"\n").encode(),env=env,capture_output=True,check=True).stdout
    try:
        gpg("--quick-gen-key","Mognitio Release Signing (ProjectCuriositas)","ed25519","cert","5y")
        def fingerprints():
            listing=gpg("--with-colons","--list-keys").decode()
            return [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        primary=fingerprints()[0]
        gpg("--quick-add-key",primary,"ed25519","sign","1y")
        apt=fingerprints()[1]
        gpg("--quick-add-key",primary,"ed25519","sign","1y")
        bundle=fingerprints()[2]
        (output/"primary-secret.asc").write_bytes(gpg("--armor","--export-secret-keys",primary))
        (online/"mognitio.asc").write_bytes(gpg("--armor","--export",primary))
        (online/"apt-subkey.asc").write_bytes(gpg("--armor","--export-secret-subkeys",apt+"!"))
        (online/"bundle-subkey.asc").write_bytes(gpg("--armor","--export-secret-subkeys",bundle+"!"))
        (online/"fingerprints.json").write_text(json.dumps({
            "primary_fingerprint":primary,"apt_signing_fingerprint":apt,
            "bundle_signing_fingerprint":bundle},indent=2)+"\n")
        print("Created offline backup and a separate online transfer directory.")
        print("Primary public fingerprint: "+primary)
        print("Back up the complete offline directory before transferring only online/.")
    finally:
        subprocess.run(["gpgconf","--homedir",str(home.resolve()),"--kill","gpg-agent"],capture_output=True)

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    main(parser.parse_args().output.resolve())
