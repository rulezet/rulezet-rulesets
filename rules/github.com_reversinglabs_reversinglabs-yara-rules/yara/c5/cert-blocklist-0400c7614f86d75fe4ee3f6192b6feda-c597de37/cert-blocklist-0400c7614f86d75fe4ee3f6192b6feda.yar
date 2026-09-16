import "pe"
rule cert_blocklist_0400c7614f86d75fe4ee3f6192b6feda {
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
            pe.signatures[i].subject contains "StackUp ApS" and
            pe.signatures[i].serial == "04:00:c7:61:4f:86:d7:5f:e4:ee:3f:61:92:b6:fe:da" and
            1626393601 <= pe.signatures[i].not_after
        )
}