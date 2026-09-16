import "pe"
rule cert_blocklist_21b991 {
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
            pe.signatures[i].subject contains "Web Nexus d.o.o." and
            pe.signatures[i].serial == "21:b9:91" and
            1125477041 <= pe.signatures[i].not_after
        )
}