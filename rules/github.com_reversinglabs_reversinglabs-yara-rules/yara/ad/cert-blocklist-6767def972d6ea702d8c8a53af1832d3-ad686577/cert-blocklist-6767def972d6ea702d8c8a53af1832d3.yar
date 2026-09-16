import "pe"
rule cert_blocklist_6767def972d6ea702d8c8a53af1832d3 {
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
            pe.signatures[i].subject contains "Guangzhou typical corner Network Technology Co., Ltd." and
            pe.signatures[i].serial == "67:67:de:f9:72:d6:ea:70:2d:8c:8a:53:af:18:32:d3" and
            1361750400 <= pe.signatures[i].not_after
        )
}