import "pe"
rule cert_blocklist_0f007898afcba5f8af8ae65d01803617 {
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
            pe.signatures[i].subject contains "TechnoElek s.r.o." and
            pe.signatures[i].serial == "0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17" and
            1638372946 <= pe.signatures[i].not_after
        )
}