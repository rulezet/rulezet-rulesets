import "pe"
rule cert_blocklist_0a590154b5980e566314122987dea548 {
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
            pe.signatures[i].subject contains "Maya logistika d.o.o." and
            pe.signatures[i].serial == "0a:59:01:54:b5:98:0e:56:63:14:12:29:87:de:a5:48" and
            1636416000 <= pe.signatures[i].not_after
        )
}