import "pe"
rule cert_blocklist_7bf27695fd20b588f2b2f173b6caf2ba {
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
            pe.signatures[i].subject contains "Game Warriors Limited" and
            pe.signatures[i].serial == "7b:f2:76:95:fd:20:b5:88:f2:b2:f1:73:b6:ca:f2:ba" and
            1662112800 <= pe.signatures[i].not_after
        )
}