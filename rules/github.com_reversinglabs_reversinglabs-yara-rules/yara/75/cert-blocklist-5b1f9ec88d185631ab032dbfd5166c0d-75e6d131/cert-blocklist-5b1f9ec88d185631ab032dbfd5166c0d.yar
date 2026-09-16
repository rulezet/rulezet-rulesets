import "pe"
rule cert_blocklist_5b1f9ec88d185631ab032dbfd5166c0d {
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
            pe.signatures[i].subject contains "TOPFLIGHT GROUP LIMITED" and
            pe.signatures[i].serial == "5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d" and
            1656028800 <= pe.signatures[i].not_after
        )
}