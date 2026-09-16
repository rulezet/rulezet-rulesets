import "pe"
rule cert_blocklist_52379131a1c69263c795a7d398db0997 {
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
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "52:37:91:31:a1:c6:92:63:c7:95:a7:d3:98:db:09:97" and
            1476748800 <= pe.signatures[i].not_after
        )
}