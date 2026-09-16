import "pe"
rule cert_blocklist_214df59fe53874cc011dd45727035f51 {
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
            pe.signatures[i].serial == "21:4d:f5:9f:e5:38:74:cc:01:1d:d4:57:27:03:5f:51" and
            1468800000 <= pe.signatures[i].not_after
        )
}