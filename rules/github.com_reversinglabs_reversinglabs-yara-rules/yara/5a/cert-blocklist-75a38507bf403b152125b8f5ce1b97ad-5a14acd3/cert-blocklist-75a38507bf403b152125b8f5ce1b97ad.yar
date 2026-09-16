import "pe"
rule cert_blocklist_75a38507bf403b152125b8f5ce1b97ad {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Zeus malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "isonet ag" and
            pe.signatures[i].serial == "75:a3:85:07:bf:40:3b:15:21:25:b8:f5:ce:1b:97:ad" and
            1395359999 <= pe.signatures[i].not_after
        )
}