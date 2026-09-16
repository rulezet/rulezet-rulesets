import "pe"
rule cert_blocklist_e573d9c8b403c41bd59ffa0a8efd4168 {
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
            pe.signatures[i].subject contains "\"VERONIKA 2\" OOO" and (
                pe.signatures[i].serial == "00:e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68" or
                pe.signatures[i].serial == "e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68"
            ) and
            1563148800 <= pe.signatures[i].not_after
        )
}