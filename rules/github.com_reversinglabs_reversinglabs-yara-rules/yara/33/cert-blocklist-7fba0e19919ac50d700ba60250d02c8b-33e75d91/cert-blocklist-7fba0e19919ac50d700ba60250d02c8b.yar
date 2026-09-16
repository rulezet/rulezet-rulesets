import "pe"
rule cert_blocklist_7fba0e19919ac50d700ba60250d02c8b {
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
            pe.signatures[i].subject contains "OOO Diamartis" and
            pe.signatures[i].serial == "7f:ba:0e:19:91:9a:c5:0d:70:0b:a6:02:50:d0:2c:8b" and
            1623196800 <= pe.signatures[i].not_after
        )
}