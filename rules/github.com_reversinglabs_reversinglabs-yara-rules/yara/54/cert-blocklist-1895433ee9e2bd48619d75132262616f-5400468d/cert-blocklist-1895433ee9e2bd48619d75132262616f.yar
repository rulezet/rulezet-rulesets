import "pe"
rule cert_blocklist_1895433ee9e2bd48619d75132262616f {
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
            pe.signatures[i].subject contains "Evetrans Ltd" and
            pe.signatures[i].serial == "18:95:43:3e:e9:e2:bd:48:61:9d:75:13:22:62:61:6f" and
            1619789516 <= pe.signatures[i].not_after
        )
}