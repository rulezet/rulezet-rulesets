import "pe"
rule cert_blocklist_1ae3c4eccecda2127d43be390a850dda {
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
            pe.signatures[i].subject contains "PARTYNET LIMITED" and
            pe.signatures[i].serial == "1a:e3:c4:ec:ce:cd:a2:12:7d:43:be:39:0a:85:0d:da" and
            1614902400 <= pe.signatures[i].not_after
        )
}