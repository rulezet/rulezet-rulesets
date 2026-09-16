import "pe"
rule cert_blocklist_15da61d7e1a631803431561674fb9b90 {
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
            pe.signatures[i].subject contains "JAY DANCE STUDIO d.o.o." and
            pe.signatures[i].serial == "15:da:61:d7:e1:a6:31:80:34:31:56:16:74:fb:9b:90" and
            1610668800 <= pe.signatures[i].not_after
        )
}