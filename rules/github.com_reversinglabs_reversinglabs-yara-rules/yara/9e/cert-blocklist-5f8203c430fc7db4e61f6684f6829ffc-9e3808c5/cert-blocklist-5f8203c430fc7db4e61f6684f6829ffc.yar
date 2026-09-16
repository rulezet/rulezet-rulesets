import "pe"
rule cert_blocklist_5f8203c430fc7db4e61f6684f6829ffc {
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
            pe.signatures[i].subject contains "Haivision Network Video" and
            pe.signatures[i].serial == "5f:82:03:c4:30:fc:7d:b4:e6:1f:66:84:f6:82:9f:fc" and
            1382572799 <= pe.signatures[i].not_after
        )
}