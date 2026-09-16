import "pe"
rule cert_blocklist_13794371c052ec0559e9b492abb25c26 {
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
            pe.signatures[i].subject contains "Carmel group LLC" and
            pe.signatures[i].serial == "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26" and
            1599177600 <= pe.signatures[i].not_after
        )
}