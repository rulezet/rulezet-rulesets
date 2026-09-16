import "pe"
rule cert_blocklist_2c1ee9b583310b5e34a1ee6945a34b26 {
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
            pe.signatures[i].subject contains "OOO Artmarket" and
            pe.signatures[i].serial == "2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26" and
            1607558400 <= pe.signatures[i].not_after
        )
}