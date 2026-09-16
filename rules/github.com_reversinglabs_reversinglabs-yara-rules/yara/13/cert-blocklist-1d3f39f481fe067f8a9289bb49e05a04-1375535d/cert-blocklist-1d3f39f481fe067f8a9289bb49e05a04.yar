import "pe"
rule cert_blocklist_1d3f39f481fe067f8a9289bb49e05a04 {
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
            pe.signatures[i].subject contains "LOGIKA, OOO" and
            pe.signatures[i].serial == "1d:3f:39:f4:81:fe:06:7f:8a:92:89:bb:49:e0:5a:04" and
            1592553220 <= pe.signatures[i].not_after
        )
}