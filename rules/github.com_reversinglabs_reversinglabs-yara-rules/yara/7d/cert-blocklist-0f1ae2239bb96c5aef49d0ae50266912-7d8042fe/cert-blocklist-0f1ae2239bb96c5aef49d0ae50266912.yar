import "pe"
rule cert_blocklist_0f1ae2239bb96c5aef49d0ae50266912 {
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
            pe.signatures[i].subject contains "Aarav Consulting Inc." and
            pe.signatures[i].serial == "0f:1a:e2:23:9b:b9:6c:5a:ef:49:d0:ae:50:26:69:12" and
            1653004800 <= pe.signatures[i].not_after
        )
}