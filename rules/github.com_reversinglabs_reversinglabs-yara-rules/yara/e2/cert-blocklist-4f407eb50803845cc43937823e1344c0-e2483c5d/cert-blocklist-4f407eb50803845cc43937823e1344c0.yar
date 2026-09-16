import "pe"
rule cert_blocklist_4f407eb50803845cc43937823e1344c0 {
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
            pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and
            pe.signatures[i].serial == "4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0" and
            1556555362 <= pe.signatures[i].not_after
        )
}