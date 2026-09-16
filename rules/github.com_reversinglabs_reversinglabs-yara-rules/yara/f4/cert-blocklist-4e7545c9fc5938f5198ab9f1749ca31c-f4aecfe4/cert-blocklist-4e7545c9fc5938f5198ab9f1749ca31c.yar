import "pe"
rule cert_blocklist_4e7545c9fc5938f5198ab9f1749ca31c {
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
            pe.signatures[i].subject contains "For M d.o.o." and
            pe.signatures[i].serial == "4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c" and
            1614297600 <= pe.signatures[i].not_after
        )
}