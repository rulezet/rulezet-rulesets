import "pe"
rule cert_blocklist_d9e834182dec62c654e775e809ac1d1b {
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
            pe.signatures[i].subject contains "FoodLehto Oy" and (
                pe.signatures[i].serial == "00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b" or
                pe.signatures[i].serial == "d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b"
            ) and
            1614297600 <= pe.signatures[i].not_after
        )
}