import "pe"
rule cert_blocklist_569e03988af60d80ce60728940850d9b {
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
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b" or
                pe.signatures[i].serial == "56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b"
            ) and
            1601006510 <= pe.signatures[i].not_after
        )
}