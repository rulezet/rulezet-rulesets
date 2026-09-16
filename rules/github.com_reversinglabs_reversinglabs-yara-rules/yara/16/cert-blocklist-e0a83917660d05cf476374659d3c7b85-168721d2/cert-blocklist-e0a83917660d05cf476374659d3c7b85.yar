import "pe"
rule cert_blocklist_e0a83917660d05cf476374659d3c7b85 {
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
            pe.signatures[i].subject contains "PIK MOTEL S.R.L." and (
                pe.signatures[i].serial == "00:e0:a8:39:17:66:0d:05:cf:47:63:74:65:9d:3c:7b:85" or
                pe.signatures[i].serial == "e0:a8:39:17:66:0d:05:cf:47:63:74:65:9d:3c:7b:85"
            ) and
            1621468800 <= pe.signatures[i].not_after
        )
}