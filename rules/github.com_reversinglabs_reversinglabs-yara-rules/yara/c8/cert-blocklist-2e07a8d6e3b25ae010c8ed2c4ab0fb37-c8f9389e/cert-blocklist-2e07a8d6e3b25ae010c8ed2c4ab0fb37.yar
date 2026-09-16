import "pe"
rule cert_blocklist_2e07a8d6e3b25ae010c8ed2c4ab0fb37 {
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
            pe.signatures[i].subject contains "Emurasoft, Inc." and
            pe.signatures[i].serial == "2e:07:a8:d6:e3:b2:5a:e0:10:c8:ed:2c:4a:b0:fb:37" and
            1650499200 <= pe.signatures[i].not_after
        )
}