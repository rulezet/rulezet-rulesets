import "pe"
rule cert_blocklist_3c98b6872fbb1f4ae37a4caa749d24c2 {
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
            pe.signatures[i].subject contains "OOO SMART" and
            pe.signatures[i].serial == "3c:98:b6:87:2f:bb:1f:4a:e3:7a:4c:aa:74:9d:24:c2" and
            1613370100 <= pe.signatures[i].not_after
        )
}