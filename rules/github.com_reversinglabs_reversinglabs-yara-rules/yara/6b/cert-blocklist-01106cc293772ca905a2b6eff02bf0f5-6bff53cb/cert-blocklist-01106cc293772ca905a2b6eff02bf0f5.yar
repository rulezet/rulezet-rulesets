import "pe"
rule cert_blocklist_01106cc293772ca905a2b6eff02bf0f5 {
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
            pe.signatures[i].subject contains "DMR Consulting Ltd." and
            pe.signatures[i].serial == "01:10:6c:c2:93:77:2c:a9:05:a2:b6:ef:f0:2b:f0:f5" and
            1627084800 <= pe.signatures[i].not_after
        )
}