import "pe"
rule cert_blocklist_760cef386b63406751ae83a9eae92342 {
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
            pe.signatures[i].subject contains "Gidrokon LLC" and
            pe.signatures[i].serial == "76:0c:ef:38:6b:63:40:67:51:ae:83:a9:ea:e9:23:42" and
            1601942400 <= pe.signatures[i].not_after
        )
}