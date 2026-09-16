import "pe"
rule cert_blocklist_0b7279068beb15ffe8060d2c56153c35 {
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
            pe.signatures[i].subject contains "Guangzhou YuanLuo Technology Co.,Ltd" and
            pe.signatures[i].serial == "0b:72:79:06:8b:eb:15:ff:e8:06:0d:2c:56:15:3c:35" and
            1350864000 <= pe.signatures[i].not_after
        )
}