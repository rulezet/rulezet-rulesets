import "pe"
rule cert_blocklist_010000000001297dba69dd {
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
            pe.signatures[i].subject contains "ROSSO INDEX K.K." and
            pe.signatures[i].serial == "01:00:00:00:00:01:29:7d:ba:69:dd" and
            1277713154 <= pe.signatures[i].not_after
        )
}