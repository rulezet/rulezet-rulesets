import "pe"
rule cert_blocklist_07b44cdbfffb78de05f4261672a67312 {
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
            pe.signatures[i].subject contains "Buster Paper Comercial Ltda" and
            pe.signatures[i].serial == "07:b4:4c:db:ff:fb:78:de:05:f4:26:16:72:a6:73:12" and
            1359503999 <= pe.signatures[i].not_after
        )
}