import "pe"
rule cert_blocklist_6ed2450ceac0f72e73fda1727e66e654 {
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
            pe.signatures[i].subject contains "Hohhot Handing Trade and Business Co., Ltd." and
            pe.signatures[i].serial == "6e:d2:45:0c:ea:c0:f7:2e:73:fd:a1:72:7e:66:e6:54" and
            1376092799 <= pe.signatures[i].not_after
        )
}