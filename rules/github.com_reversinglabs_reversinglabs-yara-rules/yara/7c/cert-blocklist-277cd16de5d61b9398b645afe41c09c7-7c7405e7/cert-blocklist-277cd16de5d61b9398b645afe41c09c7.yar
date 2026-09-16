import "pe"
rule cert_blocklist_277cd16de5d61b9398b645afe41c09c7 {
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
            pe.signatures[i].subject contains "THE SIGN COMPANY LIMITED" and
            pe.signatures[i].serial == "27:7c:d1:6d:e5:d6:1b:93:98:b6:45:af:e4:1c:09:c7" and
            1619049600 <= pe.signatures[i].not_after
        )
}