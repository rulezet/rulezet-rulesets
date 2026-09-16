import "pe"
rule cert_blocklist_5c7e78f53c31d6aa5b45de14b47eb5c4 {
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
            pe.signatures[i].subject contains "Cubic Information Systems, UAB" and
            pe.signatures[i].serial == "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4" and
            1579824000 <= pe.signatures[i].not_after
        )
}