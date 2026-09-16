import "pe"
rule cert_blocklist_0619c5e39a4fc60a32f9b07f6a4ca328 {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "06:19:c5:e3:9a:4f:c6:0a:32:f9:b0:7f:6a:4c:a3:28" and
            1475884800 <= pe.signatures[i].not_after
        )
}