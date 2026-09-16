import "pe"
rule cert_blocklist_738663f2c9e4adb3ad5306aa5e7cc548 {
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
            pe.signatures[i].subject contains "GIN-Konsalt" and
            pe.signatures[i].serial == "73:86:63:f2:c9:e4:ad:b3:ad:53:06:aa:5e:7c:c5:48" and
            1498435200 <= pe.signatures[i].not_after
        )
}