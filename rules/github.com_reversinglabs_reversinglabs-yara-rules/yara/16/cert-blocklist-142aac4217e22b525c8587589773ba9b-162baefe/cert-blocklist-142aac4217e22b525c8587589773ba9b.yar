import "pe"
rule cert_blocklist_142aac4217e22b525c8587589773ba9b {
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
            pe.signatures[i].subject contains "A.B. gostinstvo trgovina posredni\\xC5\\xA1tvo in druge storitve, d.o.o." and
            pe.signatures[i].serial == "14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b" and
            1614124800 <= pe.signatures[i].not_after
        )
}