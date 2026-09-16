import "pe"
rule cert_blocklist_2daa8d629cc0410a9482e62a0f8bf8fc {
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
            pe.signatures[i].subject contains "DON'T MISS A WORD LIMITED" and
            pe.signatures[i].serial == "2d:aa:8d:62:9c:c0:41:0a:94:82:e6:2a:0f:8b:f8:fc" and
            1543449600 <= pe.signatures[i].not_after
        )
}