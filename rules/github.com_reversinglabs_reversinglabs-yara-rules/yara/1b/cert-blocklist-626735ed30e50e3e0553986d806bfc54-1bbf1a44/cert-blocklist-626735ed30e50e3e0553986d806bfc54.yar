import "pe"
rule cert_blocklist_626735ed30e50e3e0553986d806bfc54 {
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
            pe.signatures[i].subject contains "FISH ACCOUNTING & TRANSLATING LIMITED" and
            pe.signatures[i].serial == "62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54" and
            1666742400 <= pe.signatures[i].not_after
        )
}