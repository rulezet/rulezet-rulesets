import "pe"
rule cert_blocklist_309d2e115f1fe2993ee2e063 {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "30:9d:2e:11:5f:1f:e2:99:3e:e2:e0:63" and
            1467102525 <= pe.signatures[i].not_after
        )
}