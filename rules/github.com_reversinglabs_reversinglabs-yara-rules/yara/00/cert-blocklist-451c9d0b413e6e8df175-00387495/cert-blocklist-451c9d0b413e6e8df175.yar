import "pe"
rule cert_blocklist_451c9d0b413e6e8df175 {
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
            pe.signatures[i].subject contains "PRASAD UPENDRA" and
            pe.signatures[i].serial == "45:1c:9d:0b:41:3e:6e:8d:f1:75" and
            1442275199 <= pe.signatures[i].not_after
        )
}