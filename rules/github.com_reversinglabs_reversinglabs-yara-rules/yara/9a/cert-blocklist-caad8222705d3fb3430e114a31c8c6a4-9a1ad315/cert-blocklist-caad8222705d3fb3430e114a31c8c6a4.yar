import "pe"
rule cert_blocklist_caad8222705d3fb3430e114a31c8c6a4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "ca:ad:82:22:70:5d:3f:b3:43:0e:11:4a:31:c8:c6:a4" and
            1341792000 <= pe.signatures[i].not_after
        )
}