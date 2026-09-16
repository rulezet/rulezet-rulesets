import "pe"
rule cert_blocklist_05bb162f6efe852b7bd4712fd737a61e {
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
            pe.signatures[i].subject contains "Wellpro Impact Solutions Oy" and
            pe.signatures[i].serial == "05:bb:16:2f:6e:fe:85:2b:7b:d4:71:2f:d7:37:a6:1e" and
            1628726400 <= pe.signatures[i].not_after
        )
}