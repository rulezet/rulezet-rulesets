import "pe"
rule cert_blocklist_f4d2def53bccb0dd2b7d54e4853a2fc5 {
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
            pe.signatures[i].subject contains "PETROYL GROUP, TOV" and (
                pe.signatures[i].serial == "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5" or
                pe.signatures[i].serial == "f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
            ) and
            1598347687 <= pe.signatures[i].not_after
        )
}