import "pe"
rule cert_blocklist_12705fb66bc22c68372a1c4e5fa662e2 {
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
            pe.signatures[i].subject contains "APRIL BROTHERS LTD" and
            pe.signatures[i].serial == "12:70:5f:b6:6b:c2:2c:68:37:2a:1c:4e:5f:a6:62:e2" and
            1642464000 <= pe.signatures[i].not_after
        )
}