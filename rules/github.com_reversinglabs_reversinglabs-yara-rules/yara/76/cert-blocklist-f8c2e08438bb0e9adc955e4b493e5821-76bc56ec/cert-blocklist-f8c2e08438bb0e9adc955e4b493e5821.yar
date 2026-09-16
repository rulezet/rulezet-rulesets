import "pe"
rule cert_blocklist_f8c2e08438bb0e9adc955e4b493e5821 {
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
            pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and (
                pe.signatures[i].serial == "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21" or
                pe.signatures[i].serial == "f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
            ) and
            1599523200 <= pe.signatures[i].not_after
        )
}