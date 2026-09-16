import "pe"
rule cert_blocklist_d8530214ca0f512946496b5164c61201 {
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
            pe.signatures[i].subject contains "DJ ONLINE MARKETING LIMITED" and (
                pe.signatures[i].serial == "00:d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01" or
                pe.signatures[i].serial == "d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01"
            ) and
            1595485920 <= pe.signatures[i].not_after
        )
}