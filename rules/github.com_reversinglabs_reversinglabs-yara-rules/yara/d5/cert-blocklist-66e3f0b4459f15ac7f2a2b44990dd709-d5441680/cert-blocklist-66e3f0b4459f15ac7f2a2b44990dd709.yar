import "pe"
rule cert_blocklist_66e3f0b4459f15ac7f2a2b44990dd709 {
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
            pe.signatures[i].subject contains "KOG Co., Ltd." and
            pe.signatures[i].serial == "66:e3:f0:b4:45:9f:15:ac:7f:2a:2b:44:99:0d:d7:09" and
            1320288125 <= pe.signatures[i].not_after
        )
}