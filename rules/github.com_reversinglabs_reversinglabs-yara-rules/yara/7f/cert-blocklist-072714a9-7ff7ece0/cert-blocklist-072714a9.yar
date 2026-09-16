import "pe"
rule cert_blocklist_072714a9 {
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
            pe.signatures[i].subject contains "Digisign Server ID (Enrich)" and
            pe.signatures[i].serial == "07:27:14:a9" and
            1320191999 <= pe.signatures[i].not_after
        )
}