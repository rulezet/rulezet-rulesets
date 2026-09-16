import "pe"
rule cert_blocklist_25f222ab2613dc4270b2aabc2519a101 {
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
            pe.signatures[i].subject contains "Aeroscan TOV" and
            pe.signatures[i].serial == "25:f2:22:ab:26:13:dc:42:70:b2:aa:bc:25:19:a1:01" and
            1445299200 <= pe.signatures[i].not_after
        )
}