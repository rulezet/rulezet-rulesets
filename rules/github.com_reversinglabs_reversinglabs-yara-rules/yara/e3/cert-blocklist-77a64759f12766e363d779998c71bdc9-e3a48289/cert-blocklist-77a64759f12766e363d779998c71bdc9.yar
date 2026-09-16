import "pe"
rule cert_blocklist_77a64759f12766e363d779998c71bdc9 {
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
            pe.signatures[i].subject contains "Beijing Gigabit Times Technology Co., Ltd" and
            pe.signatures[i].serial == "77:a6:47:59:f1:27:66:e3:63:d7:79:99:8c:71:bd:c9" and
            1301011199 <= pe.signatures[i].not_after
        )
}