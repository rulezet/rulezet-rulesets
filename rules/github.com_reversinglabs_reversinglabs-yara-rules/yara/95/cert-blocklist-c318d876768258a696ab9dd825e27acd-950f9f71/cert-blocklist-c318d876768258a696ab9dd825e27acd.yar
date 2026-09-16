import "pe"
rule cert_blocklist_c318d876768258a696ab9dd825e27acd {
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
            pe.signatures[i].subject contains "OOO Genezis" and (
                pe.signatures[i].serial == "00:c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd" or
                pe.signatures[i].serial == "c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd"
            ) and
            1615161600 <= pe.signatures[i].not_after
        )
}