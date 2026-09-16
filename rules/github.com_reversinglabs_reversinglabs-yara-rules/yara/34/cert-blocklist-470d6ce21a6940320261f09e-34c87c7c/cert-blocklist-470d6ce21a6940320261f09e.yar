import "pe"
rule cert_blocklist_470d6ce21a6940320261f09e {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "47:0d:6c:e2:1a:69:40:32:02:61:f0:9e" and
            1474523038 <= pe.signatures[i].not_after
        )
}