import "pe"
rule cert_blocklist_1b5190f73724399c9254cd424637996a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "1b:51:90:f7:37:24:39:9c:92:54:cd:42:46:37:99:6a" and
            980812799 <= pe.signatures[i].not_after
        )
}