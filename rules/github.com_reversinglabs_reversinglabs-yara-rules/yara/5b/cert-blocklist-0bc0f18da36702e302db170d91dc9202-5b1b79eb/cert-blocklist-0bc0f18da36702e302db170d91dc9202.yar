import "pe"
rule cert_blocklist_0bc0f18da36702e302db170d91dc9202 {
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
            pe.signatures[i].subject contains "Foresee Consulting Inc." and
            pe.signatures[i].serial == "0b:c0:f1:8d:a3:67:02:e3:02:db:17:0d:91:dc:92:02" and
            1637712000 <= pe.signatures[i].not_after
        )
}