import "pe"
rule cert_blocklist_11211eea9d0d1d1a325b5eae1b2b1951120f {
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
            pe.signatures[i].subject contains "LLC HERMES" and
            pe.signatures[i].serial == "11:21:1e:ea:9d:0d:1d:1a:32:5b:5e:ae:1b:2b:19:51:12:0f" and
            1460147212 <= pe.signatures[i].not_after
        )
}