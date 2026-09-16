import "pe"
rule cert_blocklist_57d7153a89bbf4729be87f3c927043aa {
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
            pe.signatures[i].subject contains "Open Source Developer, zhenganjun" and
            pe.signatures[i].serial == "57:d7:15:3a:89:bb:f4:72:9b:e8:7f:3c:92:70:43:aa" and
            1469059200 <= pe.signatures[i].not_after
        )
}