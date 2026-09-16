import "pe"
rule cert_blocklist_c04f5d17af872cb2c37e3367fe761d0d {
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
            pe.signatures[i].subject contains "DES SP Z O O" and (
                pe.signatures[i].serial == "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or
                pe.signatures[i].serial == "c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"
            ) and
            1594590024 <= pe.signatures[i].not_after
        )
}