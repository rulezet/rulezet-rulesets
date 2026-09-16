import "pe"
rule cert_blocklist_060d94e2ccae84536654d9daf39fef1e {
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
            pe.signatures[i].subject contains "HasCred ApS" and
            pe.signatures[i].serial == "06:0d:94:e2:cc:ae:84:53:66:54:d9:da:f3:9f:ef:1e" and
            1627948800 <= pe.signatures[i].not_after
        )
}