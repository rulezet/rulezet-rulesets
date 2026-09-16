import "pe"
rule cert_blocklist_b881a72d4117bbc38b81d3c65c792c1a {
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
            pe.signatures[i].subject contains "Red GmbH" and (
                pe.signatures[i].serial == "00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or
                pe.signatures[i].serial == "b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a"
            ) and
            1581936420 <= pe.signatures[i].not_after
        )
}