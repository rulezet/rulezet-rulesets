import "pe"
rule cert_blocklist_447f449121b883211663b7b7e2ead868 {
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
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "44:7f:44:91:21:b8:83:21:16:63:b7:b7:e2:ea:d8:68" and
            1443052800 <= pe.signatures[i].not_after
        )
}