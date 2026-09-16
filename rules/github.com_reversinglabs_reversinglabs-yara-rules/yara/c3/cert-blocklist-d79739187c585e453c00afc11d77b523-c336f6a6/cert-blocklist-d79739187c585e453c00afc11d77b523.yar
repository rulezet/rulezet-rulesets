import "pe"
rule cert_blocklist_d79739187c585e453c00afc11d77b523 {
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
            pe.signatures[i].subject contains "SAN MARINO INVESTMENTS PTY LTD" and (
                pe.signatures[i].serial == "00:d7:97:39:18:7c:58:5e:45:3c:00:af:c1:1d:77:b5:23" or
                pe.signatures[i].serial == "d7:97:39:18:7c:58:5e:45:3c:00:af:c1:1d:77:b5:23"
            ) and
            1631059200 <= pe.signatures[i].not_after
        )
}