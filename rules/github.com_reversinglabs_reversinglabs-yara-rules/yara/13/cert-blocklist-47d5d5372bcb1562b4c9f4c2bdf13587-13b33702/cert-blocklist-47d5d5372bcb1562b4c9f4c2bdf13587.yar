import "pe"
rule cert_blocklist_47d5d5372bcb1562b4c9f4c2bdf13587 {
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
            pe.signatures[i].subject contains "DTOPTOOLZ Co.,Ltd." and
            pe.signatures[i].serial == "47:d5:d5:37:2b:cb:15:62:b4:c9:f4:c2:bd:f1:35:87" and
            1400803199 <= pe.signatures[i].not_after
        )
}