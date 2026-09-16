import "pe"
rule cert_blocklist_045d57d63e13775c8f812e1864797f5a {
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
            pe.signatures[i].subject contains "Yuanyuan Mei" and
            pe.signatures[i].serial == "04:5d:57:d6:3e:13:77:5c:8f:81:2e:18:64:79:7f:5a" and
            1485043200 <= pe.signatures[i].not_after
        )
}