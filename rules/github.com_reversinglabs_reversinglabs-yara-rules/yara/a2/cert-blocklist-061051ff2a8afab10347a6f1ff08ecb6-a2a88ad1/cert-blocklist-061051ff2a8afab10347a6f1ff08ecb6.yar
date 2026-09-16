import "pe"
rule cert_blocklist_061051ff2a8afab10347a6f1ff08ecb6 {
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
            pe.signatures[i].subject contains "TACHOPARTS SP Z O O" and
            pe.signatures[i].serial == "06:10:51:ff:2a:8a:fa:b1:03:47:a6:f1:ff:08:ec:b6" and
            1606435200 <= pe.signatures[i].not_after
        )
}