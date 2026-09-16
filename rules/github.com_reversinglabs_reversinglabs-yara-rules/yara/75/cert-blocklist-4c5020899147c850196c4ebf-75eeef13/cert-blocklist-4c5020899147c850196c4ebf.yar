import "pe"
rule cert_blocklist_4c5020899147c850196c4ebf {
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
            pe.signatures[i].serial == "4c:50:20:89:91:47:c8:50:19:6c:4e:bf" and
            1476693792 <= pe.signatures[i].not_after
        )
}