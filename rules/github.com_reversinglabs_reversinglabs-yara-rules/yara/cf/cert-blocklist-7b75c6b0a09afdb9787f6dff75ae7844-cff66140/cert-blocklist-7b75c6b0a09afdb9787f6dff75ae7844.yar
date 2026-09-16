import "pe"
rule cert_blocklist_7b75c6b0a09afdb9787f6dff75ae7844 {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "7b:75:c6:b0:a0:9a:fd:b9:78:7f:6d:ff:75:ae:78:44" and
            1476662400 <= pe.signatures[i].not_after
        )
}