import "pe"
rule cert_blocklist_5f273626859ae4bc4becbbeb71e2ab2d {
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
            pe.signatures[i].serial == "5f:27:36:26:85:9a:e4:bc:4b:ec:bb:eb:71:e2:ab:2d" and
            1341792000 <= pe.signatures[i].not_after
        )
}