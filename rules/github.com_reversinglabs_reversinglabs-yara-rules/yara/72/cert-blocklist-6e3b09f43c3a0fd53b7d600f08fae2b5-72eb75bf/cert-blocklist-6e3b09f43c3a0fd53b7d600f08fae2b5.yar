import "pe"
rule cert_blocklist_6e3b09f43c3a0fd53b7d600f08fae2b5 {
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
            pe.signatures[i].subject contains "Divisible Limited" and
            pe.signatures[i].serial == "6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5" and
            1507248000 <= pe.signatures[i].not_after
        )
}