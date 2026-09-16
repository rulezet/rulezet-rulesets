import "pe"
rule cert_blocklist_73ed1b2f4bf8dd37a8ad9bb775774592 {
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
            pe.signatures[i].subject contains "5000 LIMITED" and
            pe.signatures[i].serial == "73:ed:1b:2f:4b:f8:dd:37:a8:ad:9b:b7:75:77:45:92" and
            1528243200 <= pe.signatures[i].not_after
        )
}