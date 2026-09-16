import "pe"
rule cert_blocklist_3223b4616c2687c04865bee8321726a8 {
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
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8" and
            1601337600 <= pe.signatures[i].not_after
        )
}