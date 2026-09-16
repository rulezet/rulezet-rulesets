import "pe"
rule cert_blocklist_2572b484fa0a61be7288d785d7bda7d3 {
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
            pe.signatures[i].subject contains "SILVA, OOO" and
            pe.signatures[i].serial == "25:72:b4:84:fa:0a:61:be:72:88:d7:85:d7:bd:a7:d3" and
            1495152000 <= pe.signatures[i].not_after
        )
}