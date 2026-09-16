import "pe"
rule cert_blocklist_ef2d35f2ae82a767a16be582ab0d1ba0 {
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
            pe.signatures[i].subject contains "Workstage Limited" and (
                pe.signatures[i].serial == "00:ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0" or
                pe.signatures[i].serial == "ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0"
            ) and
            1567123200 <= pe.signatures[i].not_after
        )
}