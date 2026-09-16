import "pe"
rule cert_blocklist_e161f76da3b5e4623892c8e6fda1ea3d {
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
            pe.signatures[i].subject contains "TGN Nedelica d.o.o." and (
                pe.signatures[i].serial == "00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d" or
                pe.signatures[i].serial == "e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d"
            ) and
            1604966400 <= pe.signatures[i].not_after
        )
}