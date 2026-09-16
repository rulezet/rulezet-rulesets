import "pe"
rule cert_blocklist_e953ada7e8f1438e5f7680ff599ae43e {
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
            pe.signatures[i].subject contains "KULBYT LLC" and (
                pe.signatures[i].serial == "00:e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e" or
                pe.signatures[i].serial == "e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e"
            ) and
            1614729600 <= pe.signatures[i].not_after
        )
}