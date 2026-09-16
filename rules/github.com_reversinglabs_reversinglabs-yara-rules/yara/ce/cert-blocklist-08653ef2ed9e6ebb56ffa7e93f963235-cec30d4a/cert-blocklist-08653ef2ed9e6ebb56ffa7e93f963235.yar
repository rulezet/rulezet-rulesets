import "pe"
rule cert_blocklist_08653ef2ed9e6ebb56ffa7e93f963235 {
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
            pe.signatures[i].subject contains "Haw Farm LIMITED" and
            pe.signatures[i].serial == "08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35" and
            1581465601 <= pe.signatures[i].not_after
        )
}