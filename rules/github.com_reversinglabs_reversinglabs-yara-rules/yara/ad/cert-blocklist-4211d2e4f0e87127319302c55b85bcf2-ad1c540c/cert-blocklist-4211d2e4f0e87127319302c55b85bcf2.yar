import "pe"
rule cert_blocklist_4211d2e4f0e87127319302c55b85bcf2 {
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
            pe.signatures[i].subject contains "yinsheng xie" and
            pe.signatures[i].serial == "42:11:d2:e4:f0:e8:71:27:31:93:02:c5:5b:85:bc:f2" and
            1360713599 <= pe.signatures[i].not_after
        )
}