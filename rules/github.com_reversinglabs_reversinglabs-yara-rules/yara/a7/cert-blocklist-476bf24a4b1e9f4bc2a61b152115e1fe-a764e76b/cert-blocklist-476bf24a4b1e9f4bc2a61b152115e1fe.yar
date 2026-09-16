import "pe"
rule cert_blocklist_476bf24a4b1e9f4bc2a61b152115e1fe {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and
            pe.signatures[i].serial == "47:6b:f2:4a:4b:1e:9f:4b:c2:a6:1b:15:21:15:e1:fe" and
            1414454399 <= pe.signatures[i].not_after
        )
}