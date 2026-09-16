import "pe"
rule cert_blocklist_25ba18a267d6d8e08ebc6e2457d58d1e {
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
            pe.signatures[i].subject contains "5Y TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e" and
            1648684800 <= pe.signatures[i].not_after
        )
}