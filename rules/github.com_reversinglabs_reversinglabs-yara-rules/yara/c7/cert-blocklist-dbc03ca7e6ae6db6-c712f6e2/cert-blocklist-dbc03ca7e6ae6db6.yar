import "pe"
rule cert_blocklist_dbc03ca7e6ae6db6 {
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
            pe.signatures[i].subject contains "SPIDER DEVELOPMENTS PTY LTD" and (
                pe.signatures[i].serial == "00:db:c0:3c:a7:e6:ae:6d:b6" or
                pe.signatures[i].serial == "db:c0:3c:a7:e6:ae:6d:b6"
            ) and
            1600826873 <= pe.signatures[i].not_after
        )
}