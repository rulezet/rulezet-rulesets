import "pe"
rule cert_blocklist_8fe807310d98357a59382090634b93f0 {
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
            pe.signatures[i].subject contains "MAVE MEDIA" and (
                pe.signatures[i].serial == "00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0" or
                pe.signatures[i].serial == "8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0"
            ) and
            1613433600 <= pe.signatures[i].not_after
        )
}