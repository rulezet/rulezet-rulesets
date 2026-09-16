import "pe"
rule cert_blocklist_159505e6456b9a9352f7c47168d89b96 {
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
            pe.signatures[i].subject contains "Shan Feng" and
            pe.signatures[i].serial == "15:95:05:e6:45:6b:9a:93:52:f7:c4:71:68:d8:9b:96" and
            1469404800 <= pe.signatures[i].not_after
        )
}