import "pe"
rule cert_blocklist_039e5d0e3297f574db99e1d9503853d9 {
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
            pe.signatures[i].subject contains "Cigam Software Corporativo LTDA" and
            pe.signatures[i].serial == "03:9e:5d:0e:32:97:f5:74:db:99:e1:d9:50:38:53:d9" and
            1378079999 <= pe.signatures[i].not_after
        )
}