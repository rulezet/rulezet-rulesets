import "pe"
rule cert_blocklist_55ab71a3f9dde3ef20c788dd1d5ff6c3 {
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
            pe.signatures[i].subject contains "Zhengzhoushi Tiekelian Information Technology Co.,Ltd" and
            pe.signatures[i].serial == "55:ab:71:a3:f9:dd:e3:ef:20:c7:88:dd:1d:5f:f6:c3" and
            1323907200 <= pe.signatures[i].not_after
        )
}