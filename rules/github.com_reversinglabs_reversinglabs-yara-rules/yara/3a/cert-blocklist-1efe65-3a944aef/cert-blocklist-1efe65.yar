import "pe"
rule cert_blocklist_1efe65 {
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
            pe.signatures[i].subject contains "Software Plugin Ltd." and
            pe.signatures[i].serial == "1e:fe:65" and
            1063224491 <= pe.signatures[i].not_after
        )
}