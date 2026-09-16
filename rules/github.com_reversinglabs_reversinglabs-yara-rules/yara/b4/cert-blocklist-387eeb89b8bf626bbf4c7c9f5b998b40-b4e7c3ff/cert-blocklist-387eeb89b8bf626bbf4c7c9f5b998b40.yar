import "pe"
rule cert_blocklist_387eeb89b8bf626bbf4c7c9f5b998b40 {
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
            pe.signatures[i].subject contains "ULTRA ACADEMY LTD" and
            pe.signatures[i].serial == "38:7e:eb:89:b8:bf:62:6b:bf:4c:7c:9f:5b:99:8b:40" and
            1637141034 <= pe.signatures[i].not_after
        )
}