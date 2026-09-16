import "pe"
rule cert_blocklist_1cb2d523a6bf7a066642c578de1c9be4 {
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
            pe.signatures[i].subject contains "Shenzhen Hua\\xE2\\x80\\x99nan Xingfa Electronic Equipment Firm" and
            pe.signatures[i].serial == "1c:b2:d5:23:a6:bf:7a:06:66:42:c5:78:de:1c:9b:e4" and
            1400889599 <= pe.signatures[i].not_after
        )
}