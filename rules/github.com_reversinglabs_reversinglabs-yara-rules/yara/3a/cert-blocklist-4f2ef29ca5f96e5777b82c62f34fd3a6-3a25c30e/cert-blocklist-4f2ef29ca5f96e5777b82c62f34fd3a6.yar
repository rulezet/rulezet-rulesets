import "pe"
rule cert_blocklist_4f2ef29ca5f96e5777b82c62f34fd3a6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bit9, Inc" and
            pe.signatures[i].serial == "4f:2e:f2:9c:a5:f9:6e:57:77:b8:2c:62:f3:4f:d3:a6" and
            1342051200 <= pe.signatures[i].not_after
        )
}