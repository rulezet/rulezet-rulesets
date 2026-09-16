import "pe"
rule cert_blocklist_4effa8b216e24b16202940c1bc2fa8a5 {
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
            pe.signatures[i].subject contains "Henan Maijiamai Technology Co., Ltd." and
            pe.signatures[i].serial == "4e:ff:a8:b2:16:e2:4b:16:20:29:40:c1:bc:2f:a8:a5" and
            1404691199 <= pe.signatures[i].not_after
        )
}