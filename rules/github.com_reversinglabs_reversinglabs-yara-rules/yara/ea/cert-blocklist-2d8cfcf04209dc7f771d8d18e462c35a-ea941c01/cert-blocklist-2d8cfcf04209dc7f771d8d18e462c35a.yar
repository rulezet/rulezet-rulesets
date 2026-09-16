import "pe"
rule cert_blocklist_2d8cfcf04209dc7f771d8d18e462c35a {
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
            pe.signatures[i].subject contains "AA PLUS INVEST d.o.o." and
            pe.signatures[i].serial == "2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a" and
            1631491200 <= pe.signatures[i].not_after
        )
}