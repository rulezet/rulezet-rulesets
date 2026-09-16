import "pe"
rule cert_blocklist_03943858218f35adb7073a6027555621 {
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
            pe.signatures[i].subject contains "RuN APps FOrEver lld" and
            pe.signatures[i].serial == "03:94:38:58:21:8f:35:ad:b7:07:3a:60:27:55:56:21" and
            1480550399 <= pe.signatures[i].not_after
        )
}