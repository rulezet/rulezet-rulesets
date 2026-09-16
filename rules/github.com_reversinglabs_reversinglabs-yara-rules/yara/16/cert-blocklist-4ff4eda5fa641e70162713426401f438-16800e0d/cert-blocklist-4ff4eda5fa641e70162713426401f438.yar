import "pe"
rule cert_blocklist_4ff4eda5fa641e70162713426401f438 {
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
            pe.signatures[i].subject contains "DUHANEY LIMITED" and
            pe.signatures[i].serial == "4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38" and
            1555349604 <= pe.signatures[i].not_after
        )
}