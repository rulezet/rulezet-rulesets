import "pe"
rule cert_blocklist_402e9fcba61e5eaf9c0c7b3bfd6259d9 {
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
            pe.signatures[i].subject contains "Yongli Li" and
            pe.signatures[i].serial == "40:2e:9f:cb:a6:1e:5e:af:9c:0c:7b:3b:fd:62:59:d9" and
            1477440000 <= pe.signatures[i].not_after
        )
}