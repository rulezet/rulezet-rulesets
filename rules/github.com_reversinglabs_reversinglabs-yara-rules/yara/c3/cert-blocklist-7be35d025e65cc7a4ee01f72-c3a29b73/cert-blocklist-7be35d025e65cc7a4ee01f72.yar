import "pe"
rule cert_blocklist_7be35d025e65cc7a4ee01f72 {
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
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "7b:e3:5d:02:5e:65:cc:7a:4e:e0:1f:72" and
            1594976445 <= pe.signatures[i].not_after
        )
}