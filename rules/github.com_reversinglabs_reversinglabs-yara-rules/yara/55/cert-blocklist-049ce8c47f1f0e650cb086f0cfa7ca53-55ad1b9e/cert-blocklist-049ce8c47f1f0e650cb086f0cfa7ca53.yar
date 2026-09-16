import "pe"
rule cert_blocklist_049ce8c47f1f0e650cb086f0cfa7ca53 {
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
            pe.signatures[i].subject contains "Select'Assistance Pro" and
            pe.signatures[i].serial == "04:9c:e8:c4:7f:1f:0e:65:0c:b0:86:f0:cf:a7:ca:53" and
            1393804799 <= pe.signatures[i].not_after
        )
}