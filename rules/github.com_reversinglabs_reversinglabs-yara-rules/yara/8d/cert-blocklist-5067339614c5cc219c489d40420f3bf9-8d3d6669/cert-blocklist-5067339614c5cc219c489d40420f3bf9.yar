import "pe"
rule cert_blocklist_5067339614c5cc219c489d40420f3bf9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "D-LINK CORPORATION" and
            pe.signatures[i].serial == "50:67:33:96:14:c5:cc:21:9c:48:9d:40:42:0f:3b:f9" and
            1441238400 <= pe.signatures[i].not_after
        )
}