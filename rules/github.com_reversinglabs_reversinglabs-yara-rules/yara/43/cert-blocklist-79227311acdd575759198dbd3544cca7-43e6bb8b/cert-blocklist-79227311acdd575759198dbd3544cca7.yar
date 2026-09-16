import "pe"
rule cert_blocklist_79227311acdd575759198dbd3544cca7 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "79:22:73:11:ac:dd:57:57:59:19:8d:bd:35:44:cc:a7" and
            1478131200 <= pe.signatures[i].not_after
        )
}