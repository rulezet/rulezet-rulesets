import "pe"
rule cert_blocklist_4f8b9a1ba5e60c754dbb40ddee7905e2 {
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
            pe.signatures[i].subject contains "NOX Entertainment Co., Ltd" and
            pe.signatures[i].serial == "4f:8b:9a:1b:a5:e6:0c:75:4d:bb:40:dd:ee:79:05:e2" and
            1348617599 <= pe.signatures[i].not_after
        )
}