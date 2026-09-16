import "pe"
rule cert_blocklist_462baada57570f70df76d10b9e7bf2b7 {
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
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "46:2b:aa:da:57:57:0f:70:df:76:d1:0b:9e:7b:f2:b7" and
            1551744000 <= pe.signatures[i].not_after
        )
}