import "pe"
rule cert_blocklist_4d29757c4fbfc32b97091d96e3723002 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "4d:29:75:7c:4f:bf:c3:2b:97:09:1d:96:e3:72:30:02" and
            1474848000 <= pe.signatures[i].not_after
        )
}