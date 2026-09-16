import "pe"
rule cert_blocklist_c33187fe848a65e8484ea492cb2cbb18 {
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
            pe.signatures[i].subject contains "SELCUK GUNDOGDU" and (
                pe.signatures[i].serial == "00:c3:31:87:fe:84:8a:65:e8:48:4e:a4:92:cb:2c:bb:18" or
                pe.signatures[i].serial == "c3:31:87:fe:84:8a:65:e8:48:4e:a4:92:cb:2c:bb:18"
            ) and
            1426204800 <= pe.signatures[i].not_after
        )
}