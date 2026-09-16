import "pe"
rule cert_blocklist_4b5d8ed5ca011679f141f124 {
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
            pe.signatures[i].serial == "4b:5d:8e:d5:ca:01:16:79:f1:41:f1:24" and
            1480644725 <= pe.signatures[i].not_after
        )
}