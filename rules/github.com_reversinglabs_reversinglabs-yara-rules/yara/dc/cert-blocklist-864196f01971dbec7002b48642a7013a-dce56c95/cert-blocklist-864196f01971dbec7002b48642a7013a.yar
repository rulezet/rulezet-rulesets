import "pe"
rule cert_blocklist_864196f01971dbec7002b48642a7013a {
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
            pe.signatures[i].subject contains "WLE DESENVOLVIMENTO DE SOFTWARE E ASSESSORIA LTDA EPP" and (
                pe.signatures[i].serial == "00:86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a" or
                pe.signatures[i].serial == "86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a"
            ) and
            1384300799 <= pe.signatures[i].not_after
        )
}