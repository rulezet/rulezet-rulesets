import "pe"
rule cert_blocklist_01c88ccbd219500139d1af138a9e898e {
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
            pe.signatures[i].subject contains "Raymond Yanagita" and
            pe.signatures[i].serial == "01:c8:8c:cb:d2:19:50:01:39:d1:af:13:8a:9e:89:8e" and
            1593041280 <= pe.signatures[i].not_after
        )
}