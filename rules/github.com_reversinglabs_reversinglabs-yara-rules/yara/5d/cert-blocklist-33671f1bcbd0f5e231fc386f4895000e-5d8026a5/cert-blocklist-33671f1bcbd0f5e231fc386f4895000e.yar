import "pe"
rule cert_blocklist_33671f1bcbd0f5e231fc386f4895000e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALAIS, OOO" and
            pe.signatures[i].serial == "33:67:1f:1b:cb:d0:f5:e2:31:fc:38:6f:48:95:00:0e" and
            1491868800 <= pe.signatures[i].not_after
        )
}