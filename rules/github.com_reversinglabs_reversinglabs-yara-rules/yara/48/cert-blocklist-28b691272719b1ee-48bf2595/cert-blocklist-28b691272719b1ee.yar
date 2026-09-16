import "pe"
rule cert_blocklist_28b691272719b1ee {
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
            pe.signatures[i].subject contains "2021945 Ontario Inc." and
            pe.signatures[i].serial == "28:b6:91:27:27:19:b1:ee" and
            1616410532 <= pe.signatures[i].not_after
        )
}