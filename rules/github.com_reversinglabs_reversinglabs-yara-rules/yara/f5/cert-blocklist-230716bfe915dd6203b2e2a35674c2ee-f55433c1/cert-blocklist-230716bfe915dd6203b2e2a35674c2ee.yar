import "pe"
rule cert_blocklist_230716bfe915dd6203b2e2a35674c2ee {
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
            pe.signatures[i].subject contains "Jiang Liu" and
            pe.signatures[i].serial == "23:07:16:bf:e9:15:dd:62:03:b2:e2:a3:56:74:c2:ee" and
            1472169600 <= pe.signatures[i].not_after
        )
}