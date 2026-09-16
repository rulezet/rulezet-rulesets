import "pe"
rule cert_blocklist_391ae38670ab188a5de26e07 {
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
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "39:1a:e3:86:70:ab:18:8a:5d:e2:6e:07" and
            1540832872 <= pe.signatures[i].not_after
        )
}