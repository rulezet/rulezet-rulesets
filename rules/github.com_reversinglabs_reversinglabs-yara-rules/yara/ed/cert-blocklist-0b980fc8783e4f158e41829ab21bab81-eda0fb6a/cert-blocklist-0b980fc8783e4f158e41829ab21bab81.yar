import "pe"
rule cert_blocklist_0b980fc8783e4f158e41829ab21bab81 {
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
            pe.signatures[i].subject contains "Idris Kanchwala Holding Corp." and
            pe.signatures[i].serial == "0b:98:0f:c8:78:3e:4f:15:8e:41:82:9a:b2:1b:ab:81" and
            1631750400 <= pe.signatures[i].not_after
        )
}