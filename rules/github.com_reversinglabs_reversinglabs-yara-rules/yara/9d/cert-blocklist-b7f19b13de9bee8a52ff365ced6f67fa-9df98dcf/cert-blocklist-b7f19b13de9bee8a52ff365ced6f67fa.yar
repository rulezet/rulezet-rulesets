import "pe"
rule cert_blocklist_b7f19b13de9bee8a52ff365ced6f67fa {
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
            pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and (
                pe.signatures[i].serial == "00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa" or
                pe.signatures[i].serial == "b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa"
            ) and
            1574914319 <= pe.signatures[i].not_after
        )
}