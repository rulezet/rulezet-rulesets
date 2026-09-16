import "pe"
rule cert_blocklist_07270ff9 {
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
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:0f:f9" and
            1308182400 <= pe.signatures[i].not_after
        )
}