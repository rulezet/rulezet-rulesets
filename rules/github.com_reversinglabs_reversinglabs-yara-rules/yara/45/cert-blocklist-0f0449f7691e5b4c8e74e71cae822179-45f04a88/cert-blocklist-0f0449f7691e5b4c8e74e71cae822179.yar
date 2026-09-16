import "pe"
rule cert_blocklist_0f0449f7691e5b4c8e74e71cae822179 {
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
            pe.signatures[i].subject contains "SBO INVEST" and
            pe.signatures[i].serial == "0f:04:49:f7:69:1e:5b:4c:8e:74:e7:1c:ae:82:21:79" and
            1432079999 <= pe.signatures[i].not_after
        )
}