import "pe"
rule cert_blocklist_c04f8f1e00c69e96a51bf14aab1c6ae0 {
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
            pe.signatures[i].subject contains "CHAIKA, TOV" and (
                pe.signatures[i].serial == "00:c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0" or
                pe.signatures[i].serial == "c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0"
            ) and
            1551398400 <= pe.signatures[i].not_after
        )
}