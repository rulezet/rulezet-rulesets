import "pe"
rule cert_blocklist_a7e1dc5352c3852c5523030f57f2425c {
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
            pe.signatures[i].subject contains "Pushka LLC" and (
                pe.signatures[i].serial == "00:a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c" or
                pe.signatures[i].serial == "a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c"
            ) and
            1611792000 <= pe.signatures[i].not_after
        )
}