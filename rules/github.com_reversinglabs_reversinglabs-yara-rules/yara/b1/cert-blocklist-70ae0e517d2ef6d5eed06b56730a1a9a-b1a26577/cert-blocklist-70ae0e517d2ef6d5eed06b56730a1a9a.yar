import "pe"
rule cert_blocklist_70ae0e517d2ef6d5eed06b56730a1a9a {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "70:ae:0e:51:7d:2e:f6:d5:ee:d0:6b:56:73:0a:1a:9a" and
            1475193600 <= pe.signatures[i].not_after
        )
}