import "pe"
rule cert_blocklist_e69a6de0074ece38c2f30f0d4a808456 {
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
            pe.signatures[i].subject contains "OOO Semantic" and (
                pe.signatures[i].serial == "00:e6:9a:6d:e0:07:4e:ce:38:c2:f3:0f:0d:4a:80:84:56" or
                pe.signatures[i].serial == "e6:9a:6d:e0:07:4e:ce:38:c2:f3:0f:0d:4a:80:84:56"
            ) and
            1611532800 <= pe.signatures[i].not_after
        )
}