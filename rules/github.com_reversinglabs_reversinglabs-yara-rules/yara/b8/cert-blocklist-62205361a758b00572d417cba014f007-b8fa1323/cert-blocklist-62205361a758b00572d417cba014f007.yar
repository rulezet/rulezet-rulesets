import "pe"
rule cert_blocklist_62205361a758b00572d417cba014f007 {
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
            pe.signatures[i].subject contains "UNITEKH-S, OOO" and
            pe.signatures[i].serial == "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07" and
            1590470683 <= pe.signatures[i].not_after
        )
}