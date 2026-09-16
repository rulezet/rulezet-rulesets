import "pe"
rule cert_blocklist_58a541d50f9e2fab4380c6a2ed433b82 {
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
            pe.signatures[i].serial == "58:a5:41:d5:0f:9e:2f:ab:43:80:c6:a2:ed:43:3b:82" and
            1341792000 <= pe.signatures[i].not_after
        )
}