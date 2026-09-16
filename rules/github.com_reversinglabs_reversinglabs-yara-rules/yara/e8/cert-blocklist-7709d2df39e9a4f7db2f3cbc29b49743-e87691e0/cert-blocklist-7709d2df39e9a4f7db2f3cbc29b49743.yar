import "pe"
rule cert_blocklist_7709d2df39e9a4f7db2f3cbc29b49743 {
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
            pe.signatures[i].subject contains "Grina LLC" and
            pe.signatures[i].serial == "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43" and
            1556353331 <= pe.signatures[i].not_after
        )
}