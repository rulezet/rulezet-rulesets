import "pe"
rule cert_blocklist_11212f502836a784752160351defb136cf09 {
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
            pe.signatures[i].subject contains "EVANGEL TECHNOLOGY(HK) LIMITED" and
            pe.signatures[i].serial == "11:21:2f:50:28:36:a7:84:75:21:60:35:1d:ef:b1:36:cf:09" and
            1463726573 <= pe.signatures[i].not_after
        )
}