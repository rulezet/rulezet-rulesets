import "pe"
rule cert_blocklist_95e5793f2abe0b4ec9be54fd24f76ae5 {
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
            pe.signatures[i].subject contains "Kommservice LLC" and (
                pe.signatures[i].serial == "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5" or
                pe.signatures[i].serial == "95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
            ) and
            1604933746 <= pe.signatures[i].not_after
        )
}