import "pe"
rule cert_blocklist_187d92861076e469b5b7a19e2a9fd4ba {
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
            pe.signatures[i].serial == "18:7d:92:86:10:76:e4:69:b5:b7:a1:9e:2a:9f:d4:ba" and
            1476748800 <= pe.signatures[i].not_after
        )
}