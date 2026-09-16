import "pe"
rule cert_blocklist_1a3faaeb3a8b93b2394fec36345996e6 {
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
            pe.signatures[i].subject contains "salvatore macchiarella" and
            pe.signatures[i].serial == "1a:3f:aa:eb:3a:8b:93:b2:39:4f:ec:36:34:59:96:e6" and
            1468454400 <= pe.signatures[i].not_after
        )
}