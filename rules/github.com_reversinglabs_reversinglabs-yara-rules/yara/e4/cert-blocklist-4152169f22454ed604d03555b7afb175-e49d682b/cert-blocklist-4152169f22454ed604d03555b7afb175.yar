import "pe"
rule cert_blocklist_4152169f22454ed604d03555b7afb175 {
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
            pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and
            pe.signatures[i].serial == "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75" and
            1595808000 <= pe.signatures[i].not_after
        )
}