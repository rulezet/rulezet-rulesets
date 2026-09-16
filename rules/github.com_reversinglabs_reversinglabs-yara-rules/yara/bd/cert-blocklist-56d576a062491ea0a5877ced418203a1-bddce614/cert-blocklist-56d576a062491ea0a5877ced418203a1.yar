import "pe"
rule cert_blocklist_56d576a062491ea0a5877ced418203a1 {
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
            pe.signatures[i].subject contains "Silvo LLC" and
            pe.signatures[i].serial == "56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1" and
            1596249885 <= pe.signatures[i].not_after
        )
}