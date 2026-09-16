import "pe"
rule cert_blocklist_4fbcaa289ba925b4e247809b6b028202 {
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
            pe.signatures[i].subject contains "Kimjac ApS" and
            pe.signatures[i].serial == "4f:bc:aa:28:9b:a9:25:b4:e2:47:80:9b:6b:02:82:02" and
            1588227220 <= pe.signatures[i].not_after
        )
}