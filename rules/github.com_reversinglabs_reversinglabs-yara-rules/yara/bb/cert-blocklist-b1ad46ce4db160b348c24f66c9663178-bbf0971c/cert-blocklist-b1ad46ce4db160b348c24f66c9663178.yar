import "pe"
rule cert_blocklist_b1ad46ce4db160b348c24f66c9663178 {
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
            pe.signatures[i].serial == "b1:ad:46:ce:4d:b1:60:b3:48:c2:4f:66:c9:66:31:78" and
            1341792000 <= pe.signatures[i].not_after
        )
}