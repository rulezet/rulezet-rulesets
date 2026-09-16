import "pe"
rule cert_blocklist_65cd323c2483668b90a44a711d2a6b98 {
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
            pe.signatures[i].subject contains "OOO Giperion" and
            pe.signatures[i].serial == "65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98" and
            1602547200 <= pe.signatures[i].not_after
        )
}