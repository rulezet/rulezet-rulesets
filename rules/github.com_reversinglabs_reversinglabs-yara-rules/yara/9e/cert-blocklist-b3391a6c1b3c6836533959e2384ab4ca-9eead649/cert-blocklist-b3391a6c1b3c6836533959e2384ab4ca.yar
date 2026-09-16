import "pe"
rule cert_blocklist_b3391a6c1b3c6836533959e2384ab4ca {
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
            pe.signatures[i].subject contains "VERIFIED SOFTWARE LLC" and (
                pe.signatures[i].serial == "00:b3:39:1a:6c:1b:3c:68:36:53:39:59:e2:38:4a:b4:ca" or
                pe.signatures[i].serial == "b3:39:1a:6c:1b:3c:68:36:53:39:59:e2:38:4a:b4:ca"
            ) and
            1595462400 <= pe.signatures[i].not_after
        )
}