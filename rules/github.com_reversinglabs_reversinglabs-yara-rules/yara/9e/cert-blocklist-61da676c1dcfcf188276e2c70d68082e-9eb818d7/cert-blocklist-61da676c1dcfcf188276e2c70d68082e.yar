import "pe"
rule cert_blocklist_61da676c1dcfcf188276e2c70d68082e {
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
            pe.signatures[i].subject contains "P2N ONLINE LTD" and
            pe.signatures[i].serial == "61:da:67:6c:1d:cf:cf:18:82:76:e2:c7:0d:68:08:2e" and
            1552723954 <= pe.signatures[i].not_after
        )
}