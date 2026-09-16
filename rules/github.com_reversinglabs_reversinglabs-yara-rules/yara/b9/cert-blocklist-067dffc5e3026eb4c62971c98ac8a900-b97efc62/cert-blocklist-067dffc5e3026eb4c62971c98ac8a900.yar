import "pe"
rule cert_blocklist_067dffc5e3026eb4c62971c98ac8a900 {
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
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "06:7d:ff:c5:e3:02:6e:b4:c6:29:71:c9:8a:c8:a9:00" and
            1552176000 <= pe.signatures[i].not_after
        )
}