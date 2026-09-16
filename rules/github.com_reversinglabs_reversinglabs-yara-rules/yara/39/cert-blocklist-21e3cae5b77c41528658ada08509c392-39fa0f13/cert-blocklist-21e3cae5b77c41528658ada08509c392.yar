import "pe"
rule cert_blocklist_21e3cae5b77c41528658ada08509c392 {
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
            pe.signatures[i].subject contains "Network Design International Holdings Limited" and
            pe.signatures[i].serial == "21:e3:ca:e5:b7:7c:41:52:86:58:ad:a0:85:09:c3:92" and
            1609233559 <= pe.signatures[i].not_after
        )
}