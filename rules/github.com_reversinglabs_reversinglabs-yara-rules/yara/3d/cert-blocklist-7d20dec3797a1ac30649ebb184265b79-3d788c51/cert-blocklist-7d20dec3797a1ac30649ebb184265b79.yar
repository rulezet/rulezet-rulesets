import "pe"
rule cert_blocklist_7d20dec3797a1ac30649ebb184265b79 {
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
            pe.signatures[i].subject contains "Jiang Liu" and
            pe.signatures[i].serial == "7d:20:de:c3:79:7a:1a:c3:06:49:eb:b1:84:26:5b:79" and
            1474156800 <= pe.signatures[i].not_after
        )
}