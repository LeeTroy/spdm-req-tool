#!/usr/bin/env python3
"""Make a test owner PKI for SET_CERTIFICATE.

From a responder's slot-0 chain (saved with spdm-req-tool -C chain.bin or
chain.pem), make an owner test root and an endorsement of the device's LDevID
key signed by it. The endorsement is the LDevID certificate re-signed by the
owner root: same subject, public key and SubjectKeyIdentifier, so the
certificates the responder appends (FMC alias, RT alias, DPE leaf) still
chain to it.

  make-owner-pki.py --ecc-chain ecc.bin --mldsa-chain mldsa.bin -o owner/

writes, per chain given:
  owner-ecc-root.der, owner-ecc-root.key       ECC P-384 owner root
  owner-ecc-chain.der                          root + LDevID endorsement
  owner-mldsa-root.der, owner-mldsa-root.key   ML-DSA-87 owner root
  owner-mldsa-chain.der                        root + LDevID endorsement

owner-*-chain.der is the --cert-chain for spdm-req-tool set-cert, and
owner-*-root.der the --root-ca to verify the slot afterwards. Needs OpenSSL
3.5 or later (ML-DSA).
"""
import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile

ALGS = {
    "ecc": {"newkey": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
            "digest": ["-sha384"], "name": "ECC P-384"},
    "mldsa": {"newkey": ["-newkey", "ML-DSA-87"], "digest": [], "name": "ML-DSA-87"},
}


def openssl(*args, stdin=None):
    r = subprocess.run(["openssl", *args], input=stdin, capture_output=True)
    if r.returncode:
        sys.exit("openssl %s failed:\n%s" % (" ".join(args), r.stderr.decode(errors="replace")))
    return r.stdout


def der_len(b, off):
    """Length of the DER element at off (tag, length and contents)."""
    if b[off + 1] < 0x80:
        return 2 + b[off + 1]
    n = b[off + 1] & 0x7F
    return 2 + n + int.from_bytes(b[off + 2:off + 2 + n], "big")


def split_der(b):
    certs, off = [], 0
    while off < len(b):
        if b[off] != 0x30:
            raise ValueError("not a DER certificate at offset %d" % off)
        n = der_len(b, off)
        certs.append(b[off:off + n])
        off += n
    return certs


def load_chain(path):
    """Certificates of an SPDM chain (.bin), a PEM bundle or concatenated DER."""
    data = open(path, "rb").read()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return [base64.b64decode(m) for m in re.findall(
            rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", data, re.S)]
    if data[0] == 0x30:
        return split_der(data)
    # SPDM cert chain: Length(2) Reserved(2) RootHash(hash size) certificates
    if int.from_bytes(data[0:2], "little") != len(data):
        sys.exit("%s: neither PEM, DER nor an SPDM certificate chain" % path)
    for hs in (48, 32, 64):
        try:
            return split_der(data[4 + hs:])
        except (ValueError, IndexError):
            pass
    sys.exit("%s: cannot find the certificates after the SPDM chain header" % path)


def subject(der):
    out = openssl("x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253",
                  stdin=der)
    return out.decode().strip().split("=", 1)[1]


def find_ldevid(certs, index):
    if index is not None:
        return index
    for i, c in enumerate(certs):
        if "ldevid" in subject(c).lower():
            return i
    sys.exit("no certificate with LDevID in its subject; give --ldevid-index")


def ski(der):
    text = openssl("x509", "-inform", "DER", "-noout", "-ext", "subjectKeyIdentifier",
                   stdin=der).decode()
    m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)", text)
    return m.group(1) if m else None


def make(kind, chain_path, outdir, ldevid_index, days, tmp):
    alg = ALGS[kind]
    certs = load_chain(chain_path)
    li = find_ldevid(certs, ldevid_index)
    ldevid = certs[li]
    print("%s: %d certificates, LDevID is #%d: %s" % (chain_path, len(certs), li, subject(ldevid)))

    root_key = os.path.join(outdir, "owner-%s-root.key" % kind)
    root_pem = os.path.join(tmp, "%s-root.pem" % kind)
    openssl("req", "-x509", *alg["newkey"], *alg["digest"], "-nodes", "-keyout", root_key,
            "-out", root_pem, "-days", str(days), "-subj",
            "/O=ASPEED Test/CN=Owner Test Root %s" % alg["name"],
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    root_der = openssl("x509", "-in", root_pem, "-outform", "DER")

    # Re-sign the LDevID certificate: keep subject and key, replace the
    # issuer, serial, validity and extensions.
    ldevid_pem = os.path.join(tmp, "%s-ldevid.der" % kind)
    open(ldevid_pem, "wb").write(ldevid)
    ext = os.path.join(tmp, "%s-ext.cnf" % kind)
    k = ski(ldevid)
    with open(ext, "w") as f:
        f.write("[v3]\n"
                "basicConstraints=critical,CA:TRUE\n"
                "keyUsage=critical,keyCertSign\n"
                "subjectKeyIdentifier=%s\n"
                "authorityKeyIdentifier=keyid:always\n" % (k if k else "hash"))
    endorse = openssl("x509", "-inform", "DER", "-in", ldevid_pem, "-CA", root_pem,
                      "-CAkey", root_key, *alg["digest"], "-set_serial",
                      "0x" + os.urandom(16).hex(), "-days", str(days), "-clrext",
                      "-extfile", ext, "-extensions", "v3", "-outform", "DER")

    # The endorsement must verify against the root and carry the LDevID key.
    e_pem = os.path.join(tmp, "%s-endorse.pem" % kind)
    open(e_pem, "wb").write(openssl("x509", "-inform", "DER", "-outform", "PEM", stdin=endorse))
    openssl("verify", "-CAfile", root_pem, e_pem)
    if (openssl("x509", "-inform", "DER", "-noout", "-pubkey", stdin=endorse) !=
            openssl("x509", "-inform", "DER", "-noout", "-pubkey", stdin=ldevid)):
        sys.exit("endorsement public key differs from the LDevID key")

    open(os.path.join(outdir, "owner-%s-root.der" % kind), "wb").write(root_der)
    open(os.path.join(outdir, "owner-%s-chain.der" % kind), "wb").write(root_der + endorse)
    print("  owner-%s-root.der %d bytes, owner-%s-chain.der %d bytes (root + endorsement%s)" %
          (kind, len(root_der), kind, len(root_der) + len(endorse),
           ", SKI " + k if k else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--ecc-chain", help="slot-0 chain negotiated with ECDSA P-384")
    ap.add_argument("--mldsa-chain", help="slot-0 chain negotiated with ML-DSA-87")
    ap.add_argument("-o", "--outdir", default=".", help="output directory (default .)")
    ap.add_argument("--ldevid-index", type=int,
                    help="index of the LDevID certificate (default: by subject)")
    ap.add_argument("--days", type=int, default=3650, help="validity (default 3650)")
    a = ap.parse_args()
    if not a.ecc_chain and not a.mldsa_chain:
        ap.error("give --ecc-chain and/or --mldsa-chain")
    os.makedirs(a.outdir, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        if a.ecc_chain:
            make("ecc", a.ecc_chain, a.outdir, a.ldevid_index, a.days, tmp)
        if a.mldsa_chain:
            make("mldsa", a.mldsa_chain, a.outdir, a.ldevid_index, a.days, tmp)


if __name__ == "__main__":
    main()
