import "pe"
rule cert_blocklist_2c90eaf4de3afc03ba924c719435c2a3 {
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
            pe.signatures[i].subject contains "AntiFIX s.r.o." and (
                pe.signatures[i].serial == "00:2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3" or
                pe.signatures[i].serial == "2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3"
            ) and
            1586293430 <= pe.signatures[i].not_after
        )
}