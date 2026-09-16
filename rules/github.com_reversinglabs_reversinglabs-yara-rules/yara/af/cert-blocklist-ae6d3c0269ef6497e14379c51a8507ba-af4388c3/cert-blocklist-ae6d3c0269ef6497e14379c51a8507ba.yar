import "pe"
rule cert_blocklist_ae6d3c0269ef6497e14379c51a8507ba {
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
            pe.signatures[i].subject contains "VELES PROPERTIES LIMITED" and (
                pe.signatures[i].serial == "00:ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba" or
                pe.signatures[i].serial == "ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba"
            ) and
            1578566034 <= pe.signatures[i].not_after
        )
}