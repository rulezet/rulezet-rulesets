import "pe"
rule cert_blocklist_028d50ae0c554b49148e82db5b1c2699 {
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
            pe.signatures[i].subject contains "VAS CO PTY LTD" and
            pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99" and
            1579478400 <= pe.signatures[i].not_after
        )
}