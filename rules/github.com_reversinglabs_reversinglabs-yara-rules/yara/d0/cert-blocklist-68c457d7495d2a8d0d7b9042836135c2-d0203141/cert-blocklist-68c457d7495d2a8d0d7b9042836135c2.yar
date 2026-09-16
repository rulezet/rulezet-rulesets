import "pe"
rule cert_blocklist_68c457d7495d2a8d0d7b9042836135c2 {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "68:c4:57:d7:49:5d:2a:8d:0d:7b:90:42:83:61:35:c2" and
            1476921600 <= pe.signatures[i].not_after
        )
}