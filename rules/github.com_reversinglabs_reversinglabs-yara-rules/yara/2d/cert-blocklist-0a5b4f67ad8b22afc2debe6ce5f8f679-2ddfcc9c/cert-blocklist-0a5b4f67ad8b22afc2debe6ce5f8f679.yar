import "pe"
rule cert_blocklist_0a5b4f67ad8b22afc2debe6ce5f8f679 {
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
            pe.signatures[i].subject contains "Farad LLC" and
            pe.signatures[i].serial == "0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79" and
            1607472000 <= pe.signatures[i].not_after
        )
}