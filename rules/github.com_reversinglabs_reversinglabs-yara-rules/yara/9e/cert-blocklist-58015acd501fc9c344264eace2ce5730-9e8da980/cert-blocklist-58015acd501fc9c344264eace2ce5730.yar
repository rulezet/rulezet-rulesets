import "pe"
rule cert_blocklist_58015acd501fc9c344264eace2ce5730 {
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
            pe.signatures[i].subject contains "Nanjing Ranyi Technology Co., Ltd. " and
            pe.signatures[i].serial == "58:01:5a:cd:50:1f:c9:c3:44:26:4e:ac:e2:ce:57:30" and
            1352246400 <= pe.signatures[i].not_after
        )
}