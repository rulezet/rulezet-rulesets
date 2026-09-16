import "pe"
rule cert_blocklist_2ca028d1a4de0eb743135edecf74d7af {
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
            pe.signatures[i].serial == "2c:a0:28:d1:a4:de:0e:b7:43:13:5e:de:cf:74:d7:af" and
            1341792000 <= pe.signatures[i].not_after
        )
}