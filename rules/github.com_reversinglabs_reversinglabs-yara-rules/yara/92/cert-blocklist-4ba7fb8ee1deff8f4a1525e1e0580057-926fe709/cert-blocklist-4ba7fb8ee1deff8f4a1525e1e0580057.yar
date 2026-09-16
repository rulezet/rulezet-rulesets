import "pe"
rule cert_blocklist_4ba7fb8ee1deff8f4a1525e1e0580057 {
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
            pe.signatures[i].serial == "4b:a7:fb:8e:e1:de:ff:8f:4a:15:25:e1:e0:58:00:57" and
            1341792000 <= pe.signatures[i].not_after
        )
}