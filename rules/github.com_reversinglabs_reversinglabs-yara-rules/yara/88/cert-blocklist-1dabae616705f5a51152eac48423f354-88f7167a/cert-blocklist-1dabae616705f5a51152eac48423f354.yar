import "pe"
rule cert_blocklist_1dabae616705f5a51152eac48423f354 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "1d:ab:ae:61:67:05:f5:a5:11:52:ea:c4:84:23:f3:54" and
            1470960000 <= pe.signatures[i].not_after
        )
}