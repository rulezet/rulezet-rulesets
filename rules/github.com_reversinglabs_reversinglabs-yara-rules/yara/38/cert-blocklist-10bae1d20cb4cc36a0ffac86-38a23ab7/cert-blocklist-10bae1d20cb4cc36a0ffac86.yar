import "pe"
rule cert_blocklist_10bae1d20cb4cc36a0ffac86 {
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
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "10:ba:e1:d2:0c:b4:cc:36:a0:ff:ac:86" and
            1476773830 <= pe.signatures[i].not_after
        )
}