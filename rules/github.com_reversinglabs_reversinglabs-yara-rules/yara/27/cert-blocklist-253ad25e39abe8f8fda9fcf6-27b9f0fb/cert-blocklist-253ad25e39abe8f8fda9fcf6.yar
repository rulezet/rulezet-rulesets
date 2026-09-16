import "pe"
rule cert_blocklist_253ad25e39abe8f8fda9fcf6 {
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
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "25:3a:d2:5e:39:ab:e8:f8:fd:a9:fc:f6" and
            1538662130 <= pe.signatures[i].not_after
        )
}