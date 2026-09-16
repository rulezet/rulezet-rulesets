import "pe"
rule cert_blocklist_1d36c4f439d651503589318f {
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
            pe.signatures[i].subject contains "REDWOOD MARKETING SOLUTIONS INC." and
            pe.signatures[i].serial == "1d:36:c4:f4:39:d6:51:50:35:89:31:8f" and
            1651518469 <= pe.signatures[i].not_after
        )
}