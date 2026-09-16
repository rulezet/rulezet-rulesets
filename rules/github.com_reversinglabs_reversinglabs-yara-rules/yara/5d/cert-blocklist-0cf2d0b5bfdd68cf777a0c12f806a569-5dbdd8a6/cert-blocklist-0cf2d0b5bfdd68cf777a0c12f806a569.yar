import "pe"
rule cert_blocklist_0cf2d0b5bfdd68cf777a0c12f806a569 {
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
            pe.signatures[i].subject contains "PROTIP d.o.o. - v ste\\xC4\\x8Daju" and
            pe.signatures[i].serial == "0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69" and
            1611705600 <= pe.signatures[i].not_after
        )
}