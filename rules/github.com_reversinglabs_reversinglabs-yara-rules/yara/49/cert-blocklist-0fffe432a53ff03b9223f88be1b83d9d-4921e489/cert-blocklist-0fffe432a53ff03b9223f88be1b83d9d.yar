import "pe"
rule cert_blocklist_0fffe432a53ff03b9223f88be1b83d9d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing BabyShark malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EGIS Co., Ltd." and
            pe.signatures[i].serial == "0f:ff:e4:32:a5:3f:f0:3b:92:23:f8:8b:e1:b8:3d:9d" and
            1498524050 <= pe.signatures[i].not_after
        )
}