import "pe"
rule cert_blocklist_bad35fd70025d46c56b89e32b1a3954c {
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
            pe.signatures[i].subject contains "Fort LLC" and (
                pe.signatures[i].serial == "00:ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c" or
                pe.signatures[i].serial == "ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c"
            ) and
            1604937337 <= pe.signatures[i].not_after
        )
}