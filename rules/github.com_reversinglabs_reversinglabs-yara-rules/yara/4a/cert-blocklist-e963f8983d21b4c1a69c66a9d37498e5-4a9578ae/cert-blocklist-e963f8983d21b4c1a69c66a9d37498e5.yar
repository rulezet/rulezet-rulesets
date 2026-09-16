import "pe"
rule cert_blocklist_e963f8983d21b4c1a69c66a9d37498e5 {
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
            pe.signatures[i].subject contains "Max Steinhard" and (
                pe.signatures[i].serial == "00:e9:63:f8:98:3d:21:b4:c1:a6:9c:66:a9:d3:74:98:e5" or
                pe.signatures[i].serial == "e9:63:f8:98:3d:21:b4:c1:a6:9c:66:a9:d3:74:98:e5"
            ) and
            1656288000 <= pe.signatures[i].not_after
        )
}