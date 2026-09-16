import "pe"
rule cert_blocklist_57c3717c5e2ce9a2e0cf0340c03f458e {
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
            pe.signatures[i].subject contains "Citizen Travel Ltd" and
            pe.signatures[i].serial == "57:c3:71:7c:5e:2c:e9:a2:e0:cf:03:40:c0:3f:45:8e" and
            1450915200 <= pe.signatures[i].not_after
        )
}