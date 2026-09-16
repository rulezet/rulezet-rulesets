import "pe"
rule cert_blocklist_169138a86954be1d9b264f47 {
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
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "16:91:38:a8:69:54:be:1d:9b:26:4f:47" and
            1477636474 <= pe.signatures[i].not_after
        )
}