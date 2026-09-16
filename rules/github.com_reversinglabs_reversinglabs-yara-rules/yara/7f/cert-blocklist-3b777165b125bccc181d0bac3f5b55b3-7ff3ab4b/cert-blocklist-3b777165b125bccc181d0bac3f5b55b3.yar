import "pe"
rule cert_blocklist_3b777165b125bccc181d0bac3f5b55b3 {
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
            pe.signatures[i].subject contains "STAND ALONE MUSIC LTD" and
            pe.signatures[i].serial == "3b:77:71:65:b1:25:bc:cc:18:1d:0b:ac:3f:5b:55:b3" and
            1607299200 <= pe.signatures[i].not_after
        )
}