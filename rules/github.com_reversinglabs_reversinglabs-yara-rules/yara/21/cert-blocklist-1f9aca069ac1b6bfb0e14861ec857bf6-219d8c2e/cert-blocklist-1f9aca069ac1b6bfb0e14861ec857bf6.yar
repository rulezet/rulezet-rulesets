import "pe"
rule cert_blocklist_1f9aca069ac1b6bfb0e14861ec857bf6 {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "1f:9a:ca:06:9a:c1:b6:bf:b0:e1:48:61:ec:85:7b:f6" and
            1477440000 <= pe.signatures[i].not_after
        )
}