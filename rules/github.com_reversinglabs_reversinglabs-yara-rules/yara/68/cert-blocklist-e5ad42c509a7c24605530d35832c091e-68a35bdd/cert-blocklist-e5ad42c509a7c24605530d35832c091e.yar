import "pe"
rule cert_blocklist_e5ad42c509a7c24605530d35832c091e {
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
            pe.signatures[i].subject contains "VESNA, OOO" and (
                pe.signatures[i].serial == "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e" or
                pe.signatures[i].serial == "e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
            ) and
            1600786458 <= pe.signatures[i].not_after
        )
}