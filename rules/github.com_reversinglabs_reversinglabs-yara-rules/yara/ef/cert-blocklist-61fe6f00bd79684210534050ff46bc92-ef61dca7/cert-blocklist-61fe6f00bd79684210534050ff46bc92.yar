import "pe"
rule cert_blocklist_61fe6f00bd79684210534050ff46bc92 {
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
            pe.signatures[i].subject contains "Xingning Dexin Network Technology Co., Ltd." and
            pe.signatures[i].serial == "61:fe:6f:00:bd:79:68:42:10:53:40:50:ff:46:bc:92" and
            1512000000 <= pe.signatures[i].not_after
        )
}