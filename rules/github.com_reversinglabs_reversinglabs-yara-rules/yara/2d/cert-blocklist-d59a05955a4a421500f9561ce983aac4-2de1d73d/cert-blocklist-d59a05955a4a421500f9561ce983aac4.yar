import "pe"
rule cert_blocklist_d59a05955a4a421500f9561ce983aac4 {
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
            pe.signatures[i].subject contains "Olymp LLC" and (
                pe.signatures[i].serial == "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4" or
                pe.signatures[i].serial == "d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
            ) and
            1601895290 <= pe.signatures[i].not_after
        )
}