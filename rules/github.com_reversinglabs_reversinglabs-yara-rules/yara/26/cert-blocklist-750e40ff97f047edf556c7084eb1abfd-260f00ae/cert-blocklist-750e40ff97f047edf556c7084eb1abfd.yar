import "pe"
rule cert_blocklist_750e40ff97f047edf556c7084eb1abfd {
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
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "75:0e:40:ff:97:f0:47:ed:f5:56:c7:08:4e:b1:ab:fd" and
            980899199 <= pe.signatures[i].not_after
        )
}