import "pe"
rule cert_blocklist_11690f05604445fae0de539eeeeec584 {
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
            pe.signatures[i].subject contains "Tera information Technology co.Ltd" and
            pe.signatures[i].serial == "11:69:0f:05:60:44:45:fa:e0:de:53:9e:ee:ee:c5:84" and
            1294703999 <= pe.signatures[i].not_after
        )
}