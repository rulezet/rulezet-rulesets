import "pe"
rule cert_blocklist_9a8bcfd05f86b15d0c99f50cf414bd00 {
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
            pe.signatures[i].subject contains "AI Software a.s." and (
                pe.signatures[i].serial == "00:9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00" or
                pe.signatures[i].serial == "9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00"
            ) and
            1592442000 <= pe.signatures[i].not_after
        )
}