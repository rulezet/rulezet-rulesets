import "pe"
rule cert_blocklist_4a2e337fff23e5b2a1321ffde56d1759 {
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
            pe.signatures[i].subject contains "Karolina Klimowska" and
            pe.signatures[i].serial == "4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59" and
            1660314070 <= pe.signatures[i].not_after
        )
}