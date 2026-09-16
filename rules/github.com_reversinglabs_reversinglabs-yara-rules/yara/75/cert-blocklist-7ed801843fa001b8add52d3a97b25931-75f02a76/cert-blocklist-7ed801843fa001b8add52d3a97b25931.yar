import "pe"
rule cert_blocklist_7ed801843fa001b8add52d3a97b25931 {
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
            pe.signatures[i].subject contains "AM El-Teknik ApS" and
            pe.signatures[i].serial == "7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31" and
            1614297600 <= pe.signatures[i].not_after
        )
}