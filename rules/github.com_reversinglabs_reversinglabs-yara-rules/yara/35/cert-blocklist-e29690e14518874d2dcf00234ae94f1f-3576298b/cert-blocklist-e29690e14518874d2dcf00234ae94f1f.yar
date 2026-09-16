import "pe"
rule cert_blocklist_e29690e14518874d2dcf00234ae94f1f {
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
            pe.signatures[i].subject contains "GRIND & TAMP ENTERPRISES PTY LTD" and (
                pe.signatures[i].serial == "00:e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f" or
                pe.signatures[i].serial == "e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f"
            ) and
            1570838400 <= pe.signatures[i].not_after
        )
}