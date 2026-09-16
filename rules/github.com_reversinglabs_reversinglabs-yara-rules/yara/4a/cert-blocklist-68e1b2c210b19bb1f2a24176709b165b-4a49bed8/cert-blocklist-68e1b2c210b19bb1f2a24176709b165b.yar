import "pe"
rule cert_blocklist_68e1b2c210b19bb1f2a24176709b165b {
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
            pe.signatures[i].serial == "68:e1:b2:c2:10:b1:9b:b1:f2:a2:41:76:70:9b:16:5b" and
            1474502400 <= pe.signatures[i].not_after
        )
}