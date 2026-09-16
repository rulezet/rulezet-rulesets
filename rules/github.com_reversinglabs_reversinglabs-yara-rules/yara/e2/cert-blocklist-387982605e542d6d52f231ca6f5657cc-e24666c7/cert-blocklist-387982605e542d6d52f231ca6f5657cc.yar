import "pe"
rule cert_blocklist_387982605e542d6d52f231ca6f5657cc {
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
            pe.signatures[i].serial == "38:79:82:60:5e:54:2d:6d:52:f2:31:ca:6f:56:57:cc" and
            1475884800 <= pe.signatures[i].not_after
        )
}