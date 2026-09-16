import "pe"
rule cert_blocklist_119acead668bad57a48b4f42f294f8f0 {
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
            pe.signatures[i].subject contains "PB03 TRANSPORT LTD." and
            pe.signatures[i].serial == "11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0" and
            1619654400 <= pe.signatures[i].not_after
        )
}