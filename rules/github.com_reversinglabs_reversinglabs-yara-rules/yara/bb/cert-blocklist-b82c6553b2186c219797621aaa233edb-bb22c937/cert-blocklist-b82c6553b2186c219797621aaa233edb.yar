import "pe"
rule cert_blocklist_b82c6553b2186c219797621aaa233edb {
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
            pe.signatures[i].subject contains "MC Commerce SP Z o o" and (
                pe.signatures[i].serial == "00:b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db" or
                pe.signatures[i].serial == "b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db"
            ) and
            1585785600 <= pe.signatures[i].not_after
        )
}