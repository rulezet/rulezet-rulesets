import "pe"
rule cert_blocklist_0a466553a6391aafd181b400266c7b18 {
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
            pe.signatures[i].subject contains "PhaseQ Limited" and
            pe.signatures[i].serial == "0a:46:65:53:a6:39:1a:af:d1:81:b4:00:26:6c:7b:18" and
            1555545600 <= pe.signatures[i].not_after
        )
}