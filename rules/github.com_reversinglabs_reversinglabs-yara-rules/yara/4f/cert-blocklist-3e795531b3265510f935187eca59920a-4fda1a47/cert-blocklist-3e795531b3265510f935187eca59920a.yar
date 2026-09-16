import "pe"
rule cert_blocklist_3e795531b3265510f935187eca59920a {
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
            pe.signatures[i].subject contains "sasha catering ltd" and
            pe.signatures[i].serial == "3e:79:55:31:b3:26:55:10:f9:35:18:7e:ca:59:92:0a" and
            1557243644 <= pe.signatures[i].not_after
        )
}