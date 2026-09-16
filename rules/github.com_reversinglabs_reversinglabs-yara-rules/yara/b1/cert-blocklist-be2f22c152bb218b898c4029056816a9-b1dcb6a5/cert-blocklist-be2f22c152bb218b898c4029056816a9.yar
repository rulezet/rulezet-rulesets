import "pe"
rule cert_blocklist_be2f22c152bb218b898c4029056816a9 {
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
            pe.signatures[i].subject contains "Marts GmbH" and (
                pe.signatures[i].serial == "00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9" or
                pe.signatures[i].serial == "be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9"
            ) and
            1676246400 <= pe.signatures[i].not_after
        )
}