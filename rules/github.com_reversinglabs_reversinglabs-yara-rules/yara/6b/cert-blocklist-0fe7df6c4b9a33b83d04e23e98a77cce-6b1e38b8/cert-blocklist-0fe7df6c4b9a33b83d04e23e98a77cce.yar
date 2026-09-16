import "pe"
rule cert_blocklist_0fe7df6c4b9a33b83d04e23e98a77cce {
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
            pe.signatures[i].subject contains "PIXELPLUS CO., LTD." and
            pe.signatures[i].serial == "0f:e7:df:6c:4b:9a:33:b8:3d:04:e2:3e:98:a7:7c:ce" and
            1396310399 <= pe.signatures[i].not_after
        )
}