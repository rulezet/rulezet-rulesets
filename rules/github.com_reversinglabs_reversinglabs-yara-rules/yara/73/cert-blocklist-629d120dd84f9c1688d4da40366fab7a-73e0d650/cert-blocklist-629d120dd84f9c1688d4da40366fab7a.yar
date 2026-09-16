import "pe"
rule cert_blocklist_629d120dd84f9c1688d4da40366fab7a {
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
            pe.signatures[i].subject contains "Delta Controls" and
            pe.signatures[i].serial == "62:9d:12:0d:d8:4f:9c:16:88:d4:da:40:36:6f:ab:7a" and
            1306799999 <= pe.signatures[i].not_after
        )
}