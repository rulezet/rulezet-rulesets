import "pe"
rule cert_blocklist_bde1d6dc3622724f427a39e6a34f5124 {
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
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:bd:e1:d6:dc:36:22:72:4f:42:7a:39:e6:a3:4f:51:24" or
                pe.signatures[i].serial == "bd:e1:d6:dc:36:22:72:4f:42:7a:39:e6:a3:4f:51:24"
            ) and
            1628553600 <= pe.signatures[i].not_after
        )
}