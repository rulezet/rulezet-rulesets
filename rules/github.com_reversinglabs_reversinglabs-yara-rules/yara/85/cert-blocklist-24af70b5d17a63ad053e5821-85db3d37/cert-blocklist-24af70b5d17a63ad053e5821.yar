import "pe"
rule cert_blocklist_24af70b5d17a63ad053e5821 {
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
            pe.signatures[i].serial == "24:af:70:b5:d1:7a:63:ad:05:3e:58:21" and
            1474179615 <= pe.signatures[i].not_after
        )
}