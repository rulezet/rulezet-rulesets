import "pe"
rule cert_blocklist_74fedf0f8398060fa8378c6d174465c8 {
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
            pe.signatures[i].subject contains "DOCS PTY LTD" and
            pe.signatures[i].serial == "74:fe:df:0f:83:98:06:0f:a8:37:8c:6d:17:44:65:c8" and
            1566172800 <= pe.signatures[i].not_after
        )
}