import "pe"
rule cert_blocklist_0c76da9c910c4e2c9efe15d058933c4c {
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
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c" and
            1308182400 <= pe.signatures[i].not_after
        )
}