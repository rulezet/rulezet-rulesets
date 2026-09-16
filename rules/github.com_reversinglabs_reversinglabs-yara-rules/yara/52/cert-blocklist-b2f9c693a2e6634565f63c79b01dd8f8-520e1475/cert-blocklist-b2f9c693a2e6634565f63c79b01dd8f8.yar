import "pe"
rule cert_blocklist_b2f9c693a2e6634565f63c79b01dd8f8 {
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
            pe.signatures[i].subject contains "PHL E STATE ApS" and (
                pe.signatures[i].serial == "00:b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8" or
                pe.signatures[i].serial == "b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}