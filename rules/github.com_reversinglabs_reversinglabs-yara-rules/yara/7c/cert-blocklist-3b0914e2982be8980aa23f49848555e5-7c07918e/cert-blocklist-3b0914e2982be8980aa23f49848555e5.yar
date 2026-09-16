import "pe"
rule cert_blocklist_3b0914e2982be8980aa23f49848555e5 {
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
            pe.signatures[i].subject contains "Office Rat s.r.o." and
            pe.signatures[i].serial == "3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5" and
            1643155200 <= pe.signatures[i].not_after
        )
}