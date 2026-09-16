import "pe"
rule cert_blocklist_1aec3d3f752a38617c1d7a677d0b5591 {
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
            pe.signatures[i].subject contains "SILVER d.o.o." and
            pe.signatures[i].serial == "1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91" and
            1611705600 <= pe.signatures[i].not_after
        )
}