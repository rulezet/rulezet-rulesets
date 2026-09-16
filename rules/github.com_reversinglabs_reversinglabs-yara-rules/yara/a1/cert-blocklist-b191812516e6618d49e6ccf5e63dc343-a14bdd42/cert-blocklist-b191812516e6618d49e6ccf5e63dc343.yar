import "pe"
rule cert_blocklist_b191812516e6618d49e6ccf5e63dc343 {
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
            pe.signatures[i].serial == "b1:91:81:25:16:e6:61:8d:49:e6:cc:f5:e6:3d:c3:43" and
            1341792000 <= pe.signatures[i].not_after
        )
}