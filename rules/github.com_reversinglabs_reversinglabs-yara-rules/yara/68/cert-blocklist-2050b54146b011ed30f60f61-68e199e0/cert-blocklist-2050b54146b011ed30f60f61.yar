import "pe"
rule cert_blocklist_2050b54146b011ed30f60f61 {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "20:50:b5:41:46:b0:11:ed:30:f6:0f:61" and
            1476773926 <= pe.signatures[i].not_after
        )
}