import "pe"
rule cert_blocklist_4679c5398a279318365fd77a84445699 {
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
            pe.signatures[i].subject contains "HURT GROUP HOLDINGS LIMITED" and
            pe.signatures[i].serial == "46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99" and
            1643846400 <= pe.signatures[i].not_after
        )
}