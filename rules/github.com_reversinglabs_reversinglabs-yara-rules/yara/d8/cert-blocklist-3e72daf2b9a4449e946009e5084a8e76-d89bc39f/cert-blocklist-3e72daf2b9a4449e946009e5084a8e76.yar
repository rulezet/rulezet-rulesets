import "pe"
rule cert_blocklist_3e72daf2b9a4449e946009e5084a8e76 {
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
            pe.signatures[i].subject contains "OOO Infoteh63" and
            pe.signatures[i].serial == "3e:72:da:f2:b9:a4:44:9e:94:60:09:e5:08:4a:8e:76" and
            1591787570 <= pe.signatures[i].not_after
        )
}