import "pe"
rule cert_blocklist_76d8d908eed2f9857dc5676a680ceac9 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "76:d8:d9:08:ee:d2:f9:85:7d:c5:67:6a:68:0c:ea:c9" and
            1467158400 <= pe.signatures[i].not_after
        )
}