"""Vulnerability-manifestation MOTIFS.

A motif is an ARCHITECTURAL PATTERN where a known vulnerability class would matter —
matched from public FIPS-artifact signals (identified components, interfaces,
services, archetype, and SP keywords). A match means *"the corpus reveals the
pattern where this bug class is relevant,"* NOT *"the module is vulnerable."* Each
motif carries a real external-research anchor and an explicit can/cannot line.
"""
import re
from components import _strong_fields, _body_fields

_NETLIB = {"OpenSSL", "GnuTLS", "mbedTLS", "wolfSSL", "NSS", "BoringSSL", "LibreSSL"}
_BOOT_KINDS = {"bootloader", "firmware"}
_DEBUG_IFACES = {"JTAG", "Serial/UART", "SPI", "SMBus/I2C", "USB"}

# name -> (description, external anchor, can-say / cannot-say)
MOTIF_INFO = {
    "boot-chain verification": (
        "Bootloader / verified-boot / signed-image verification path is present.",
        "Binarly U-Boot FIT signature-verification bypass (CVE-2026-46728, U-Boot < 2026.04)",
        "can: the boot-integrity verification surface exists. cannot: exact bootloader version, whether the affected path is built in, exploitability."),
    "firmware-update authentication": (
        "Firmware/image update path with signature/authenticity checking.",
        "signed-firmware / anti-rollback bypass classes",
        "can: an update-authentication path likely exists. cannot: whether the implementation is vulnerable."),
    "network crypto parser/protocol": (
        "A named TLS/crypto library is consumed by a network service (TLS/SSH/IKE) — handshake / X.509 / ASN.1 parsing surface.",
        "OpenSSL/GnuTLS handshake & certificate-parsing CVEs",
        "can: named component has CVE pressure and a plausibly-consuming network service. cannot: whether the vulnerable path is reachable pre-auth."),
    "debug/recovery interface": (
        "Local debug / recovery / update-media interface exposed (JTAG/UART/SPI/I2C/USB/DFU/recovery).",
        "debug-port and recovery-mode abuse classes",
        "can: a local/debug/update surface is listed. cannot: whether it is enabled in production."),
    "kernel crypto consumer": (
        "Linux-kernel crypto exposed through consumers (IPsec, storage, VPN, TLS offload, filesystem crypto).",
        "kernel crypto-subsystem CVEs",
        "can: possible downstream kernel-crypto consumers. cannot: which subsystem is actually enabled/exposed."),
    "HSM/SE firmware trust anchor": (
        "High-value HSM / secure-element trust boundary with a firmware/update path.",
        "HSM / secure-element firmware-lineage and update-path classes",
        "can: a high-impact firmware trust boundary exists. cannot: firmware lineage, patchability, production config."),
}

_KW = lambda blob, *ws: any(w in blob for w in ws)

def match_motifs(record, components, ifaces, net_svc, arch):
    blob = (_strong_fields(record) + " \n " + _body_fields(record)).lower()
    names = {c["name"] for c in components}
    kinds = {c["kind"] for c in components}
    m = []
    # boot-chain: require a boot/firmware COMPONENT or boot-SPECIFIC keywords — NOT
    # generic "signature verification" (that is the RSA/ECDSA SigVer algorithm op).
    if (kinds & _BOOT_KINDS) or _KW(blob, "flattened image tree", "fit image", "verified boot",
                                    "secure boot", "signed image", "signed firmware", "boot image", "bootloader"):
        m.append("boot-chain verification")
    if _KW(blob, "firmware update", "firmware upgrade", "image update") and \
       _KW(blob, "signed", "authenticat", " lms", " hss", "secure boot", "anti-rollback", "rollback", "signature"):
        m.append("firmware-update authentication")
    if (names & _NETLIB) and net_svc:
        m.append("network crypto parser/protocol")
    if (set(ifaces) & _DEBUG_IFACES) or _KW(blob, "\bdfu\b", "recovery mode", "debug port"):
        m.append("debug/recovery interface")
    if "Linux kernel" in names or arch == "OS/kernel crypto":
        m.append("kernel crypto consumer")
    if arch in ("HSM/accelerator", "Secure element/SoC") and ((kinds & _BOOT_KINDS) or _KW(blob, "firmware")):
        m.append("HSM/SE firmware trust anchor")
    return m
