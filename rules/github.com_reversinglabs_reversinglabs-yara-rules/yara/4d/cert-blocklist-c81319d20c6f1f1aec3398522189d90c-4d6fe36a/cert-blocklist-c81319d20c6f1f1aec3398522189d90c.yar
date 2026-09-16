import "pe"
rule cert_blocklist_c81319d20c6f1f1aec3398522189d90c {
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
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c" or
                pe.signatures[i].serial == "c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c"
            ) and
            1643500800 <= pe.signatures[i].not_after
        )
}