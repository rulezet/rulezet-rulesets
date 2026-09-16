import "pe"
rule cert_blocklist_0b6d8152f4a06ba781c6677eea5ab74b {
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
            pe.signatures[i].subject contains "GLARYSOFT LTD" and
            pe.signatures[i].serial == "0b:6d:81:52:f4:a0:6b:a7:81:c6:67:7e:ea:5a:b7:4b" and
            1568246400 <= pe.signatures[i].not_after
        )
}