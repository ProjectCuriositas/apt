#!/usr/bin/env python3
"""Validate and register only an encrypted APT subkey using gh's secret API."""
import argparse
import contextlib
import getpass
import json
from pathlib import Path
import subprocess
import tempfile
from build import key_environment

parser=argparse.ArgumentParser()
parser.add_argument("transfer",type=Path)
args=parser.parse_args()
config=json.loads((args.transfer/"fingerprints.json").read_text())
approved=json.loads((Path(__file__).resolve().parent.parent/"repository.json").read_text())
if any(approved.get(field)!=config[field] for field in
       ("primary_fingerprint","apt_signing_fingerprint","bundle_signing_fingerprint")):
    raise ValueError("Public fingerprints must be reviewed and committed before registering secrets")
secret=(args.transfer/"apt-subkey.asc").read_text()
with tempfile.TemporaryDirectory(prefix="apt-key-check-") as temporary, contextlib.ExitStack() as cleanup:
    path=Path(temporary)
    cleanup.callback(subprocess.run,["gpgconf","--homedir",str(path/"gnupg"),"--kill","gpg-agent"],capture_output=True)
    env=key_environment(path,config,secret,args.transfer/"mognitio.asc")
    password=getpass.getpass("APT subkey passphrase (registered as an environment secret): ")
    payload=path/"probe";payload.write_bytes(b"APT signing subkey setup probe\n")
    subprocess.run(["gpg","--batch","--pinentry-mode","loopback","--passphrase-fd","0",
        "--local-user",config["apt_signing_fingerprint"]+"!","--detach-sign",str(payload)],
        input=(password+"\n").encode(),env=env,capture_output=True,check=True)
    for name,value in [("APT_SIGNING_KEY",secret),("APT_SIGNING_PASSPHRASE",password)]:
        subprocess.run(["gh","secret","set",name,"--repo","ProjectCuriositas/apt","--env","release-signing"],
            input=value.encode(),check=True,capture_output=True)
print("APT signing environment secrets registered. No primary secret was uploaded.")
