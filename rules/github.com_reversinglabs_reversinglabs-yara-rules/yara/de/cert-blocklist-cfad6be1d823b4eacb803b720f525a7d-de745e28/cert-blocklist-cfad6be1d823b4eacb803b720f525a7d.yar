import "pe"
rule cert_blocklist_cfad6be1d823b4eacb803b720f525a7d {
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
            pe.signatures[i].subject contains "Sistema LLC" and (
                pe.signatures[i].serial == "00:cf:ad:6b:e1:d8:23:b4:ea:cb:80:3b:72:0f:52:5a:7d" or
                pe.signatures[i].serial == "cf:ad:6b:e1:d8:23:b4:ea:cb:80:3b:72:0f:52:5a:7d"
            ) and
            1627430400 <= pe.signatures[i].not_after
        )
}