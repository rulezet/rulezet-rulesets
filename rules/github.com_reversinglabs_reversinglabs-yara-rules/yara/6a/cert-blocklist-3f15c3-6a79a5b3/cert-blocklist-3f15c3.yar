import "pe"
rule cert_blocklist_3f15c3 {
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
            pe.signatures[i].subject contains "Certified Software" and
            pe.signatures[i].serial == "3f:15:c3" and
            1110577130 <= pe.signatures[i].not_after
        )
}