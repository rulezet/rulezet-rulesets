import "pe"
rule cert_blocklist_063a7d09107eddd8aa1f733634c6591b {
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
            pe.signatures[i].subject contains "Smart Line Logistics" and
            pe.signatures[i].serial == "06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b" and
            1605712706 <= pe.signatures[i].not_after
        )
}