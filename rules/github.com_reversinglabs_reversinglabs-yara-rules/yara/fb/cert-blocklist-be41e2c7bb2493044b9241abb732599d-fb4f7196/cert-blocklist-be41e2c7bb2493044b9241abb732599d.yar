import "pe"
rule cert_blocklist_be41e2c7bb2493044b9241abb732599d {
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
            pe.signatures[i].subject contains "Company Babylon" and (
                pe.signatures[i].serial == "00:be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d" or
                pe.signatures[i].serial == "be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d"
            ) and
            1589146251 <= pe.signatures[i].not_after
        )
}