import "pe"
rule cert_blocklist_01314476 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid" and
            pe.signatures[i].serial == "01:31:44:76" and
            1308182400 <= pe.signatures[i].not_after
        )
}