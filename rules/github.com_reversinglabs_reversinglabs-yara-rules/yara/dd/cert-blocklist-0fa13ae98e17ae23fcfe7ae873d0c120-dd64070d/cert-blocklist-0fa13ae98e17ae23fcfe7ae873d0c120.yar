import "pe"
rule cert_blocklist_0fa13ae98e17ae23fcfe7ae873d0c120 {
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
            pe.signatures[i].subject contains "KLAKSON, LLC" and
            pe.signatures[i].serial == "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20" and
            1597276801 <= pe.signatures[i].not_after
        )
}