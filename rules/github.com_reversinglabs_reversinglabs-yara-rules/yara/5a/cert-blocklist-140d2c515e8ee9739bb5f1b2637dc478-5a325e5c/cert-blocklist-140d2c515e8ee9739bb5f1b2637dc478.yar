import "pe"
rule cert_blocklist_140d2c515e8ee9739bb5f1b2637dc478 {
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
            pe.signatures[i].serial == "14:0d:2c:51:5e:8e:e9:73:9b:b5:f1:b2:63:7d:c4:78" and
            1386806400 <= pe.signatures[i].not_after
        )
}