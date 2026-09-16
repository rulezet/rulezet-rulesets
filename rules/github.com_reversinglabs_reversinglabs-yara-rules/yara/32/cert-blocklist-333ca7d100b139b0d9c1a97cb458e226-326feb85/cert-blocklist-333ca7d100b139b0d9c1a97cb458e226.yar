import "pe"
rule cert_blocklist_333ca7d100b139b0d9c1a97cb458e226 {
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
            pe.signatures[i].subject contains "FSE, d.o.o." and
            pe.signatures[i].serial == "33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26" and
            1608076800 <= pe.signatures[i].not_after
        )
}