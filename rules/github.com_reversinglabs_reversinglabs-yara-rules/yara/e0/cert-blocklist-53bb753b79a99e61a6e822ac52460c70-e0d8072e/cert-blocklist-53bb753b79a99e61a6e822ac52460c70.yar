import "pe"
rule cert_blocklist_53bb753b79a99e61a6e822ac52460c70 {
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
            pe.signatures[i].subject contains "\\xEB\\x8D\\xB0\\xEC\\x8A\\xA4\\xED\\x81\\xAC\\xED\\x83\\x91\\xEC\\x95\\x84\\xEC\\x9D\\xB4\\xEC\\xBD\\x98" and
            pe.signatures[i].serial == "53:bb:75:3b:79:a9:9e:61:a6:e8:22:ac:52:46:0c:70" and
            1400543999 <= pe.signatures[i].not_after
        )
}