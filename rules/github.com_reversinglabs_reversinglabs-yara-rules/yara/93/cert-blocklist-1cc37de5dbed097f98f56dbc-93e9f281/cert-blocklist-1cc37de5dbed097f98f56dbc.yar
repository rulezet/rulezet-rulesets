import "pe"
rule cert_blocklist_1cc37de5dbed097f98f56dbc {
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
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "1c:c3:7d:e5:db:ed:09:7f:98:f5:6d:bc" and
            1476693977 <= pe.signatures[i].not_after
        )
}