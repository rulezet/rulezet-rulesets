import "pe"
rule cert_blocklist_2df9f7eb6cdc5ca243b33122e3941e25 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "2d:f9:f7:eb:6c:dc:5c:a2:43:b3:31:22:e3:94:1e:25" and
            1341792000 <= pe.signatures[i].not_after
        )
}