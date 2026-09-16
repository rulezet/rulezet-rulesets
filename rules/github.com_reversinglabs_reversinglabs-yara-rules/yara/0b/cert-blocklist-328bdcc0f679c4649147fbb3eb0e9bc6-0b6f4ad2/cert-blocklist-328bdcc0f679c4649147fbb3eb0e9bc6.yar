import "pe"
rule cert_blocklist_328bdcc0f679c4649147fbb3eb0e9bc6 {
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
            pe.signatures[i].subject contains "Nooly Systems LTD" and
            pe.signatures[i].serial == "32:8b:dc:c0:f6:79:c4:64:91:47:fb:b3:eb:0e:9b:c6" and
            1204847999 <= pe.signatures[i].not_after
        )
}