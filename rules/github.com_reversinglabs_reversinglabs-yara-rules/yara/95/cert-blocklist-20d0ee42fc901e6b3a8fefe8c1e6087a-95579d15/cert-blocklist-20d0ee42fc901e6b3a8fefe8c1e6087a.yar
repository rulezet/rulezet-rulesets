import "pe"
rule cert_blocklist_20d0ee42fc901e6b3a8fefe8c1e6087a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SJ SYSTEM" and
            pe.signatures[i].serial == "20:d0:ee:42:fc:90:1e:6b:3a:8f:ef:e8:c1:e6:08:7a" and
            1391299199 <= pe.signatures[i].not_after
        )
}