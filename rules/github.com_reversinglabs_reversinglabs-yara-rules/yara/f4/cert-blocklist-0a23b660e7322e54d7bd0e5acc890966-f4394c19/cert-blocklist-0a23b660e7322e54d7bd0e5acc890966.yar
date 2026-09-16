import "pe"
rule cert_blocklist_0a23b660e7322e54d7bd0e5acc890966 {
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
            pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and
            pe.signatures[i].serial == "0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66" and
            1601254800 <= pe.signatures[i].not_after
        )
}