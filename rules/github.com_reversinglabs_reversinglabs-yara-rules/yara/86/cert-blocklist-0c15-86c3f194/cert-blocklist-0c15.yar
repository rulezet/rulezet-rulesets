import "pe"
rule cert_blocklist_0c15 {
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
            pe.signatures[i].subject contains "William Richard John" and
            pe.signatures[i].serial == "0c:15" and
            1387324799 <= pe.signatures[i].not_after
        )
}