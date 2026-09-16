import "pe"
rule cert_blocklist_06473c3c19d9e1a9429b58b6faec2967 {
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
            pe.signatures[i].subject contains "Digital Leadership Solutions Limited" and
            pe.signatures[i].serial == "06:47:3c:3c:19:d9:e1:a9:42:9b:58:b6:fa:ec:29:67" and
            1581984001 <= pe.signatures[i].not_after
        )
}