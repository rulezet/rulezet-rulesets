import "pe"
rule cert_blocklist_73e2f34c9c2435f29bbe0a3c {
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
            pe.signatures[i].serial == "73:e2:f3:4c:9c:24:35:f2:9b:be:0a:3c" and
            1480312984 <= pe.signatures[i].not_after
        )
}