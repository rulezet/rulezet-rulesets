import "pe"
rule cert_blocklist_54a6d33f73129e0ef059ccf51be0c35e {
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
            pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and
            pe.signatures[i].serial == "54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e" and
            1607100127 <= pe.signatures[i].not_after
        )
}