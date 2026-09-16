import "pe"
rule cert_blocklist_4fe68d48634893d18de040d8f1c289d2 {
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
            pe.signatures[i].subject contains "Xinghua Yile Network Tech Co.,Ltd." and
            pe.signatures[i].serial == "4f:e6:8d:48:63:48:93:d1:8d:e0:40:d8:f1:c2:89:d2" and
            1371081600 <= pe.signatures[i].not_after
        )
}