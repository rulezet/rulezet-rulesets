import "pe"
rule cert_blocklist_7a632a6ecfc6c49ec1f42f76 {
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
            pe.signatures[i].serial == "7a:63:2a:6e:cf:c6:c4:9e:c1:f4:2f:76" and
            1474959780 <= pe.signatures[i].not_after
        )
}