import "pe"
rule cert_blocklist_7ab21306b11ff280a93fc445876988ab {
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
            pe.signatures[i].subject contains "ABC BIOS d.o.o." and
            pe.signatures[i].serial == "7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab" and
            1611014400 <= pe.signatures[i].not_after
        )
}