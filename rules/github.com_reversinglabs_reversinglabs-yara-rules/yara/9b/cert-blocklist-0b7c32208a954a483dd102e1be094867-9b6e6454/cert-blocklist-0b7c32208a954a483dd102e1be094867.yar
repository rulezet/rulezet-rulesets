import "pe"
rule cert_blocklist_0b7c32208a954a483dd102e1be094867 {
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
            pe.signatures[i].subject contains "Win Sp Z O O" and
            pe.signatures[i].serial == "0b:7c:32:20:8a:95:4a:48:3d:d1:02:e1:be:09:48:67" and
            1583884800 <= pe.signatures[i].not_after
        )
}