import "pe"
rule cert_blocklist_610039d6349ee531e4caa3a65d100c7d {
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
            pe.signatures[i].subject contains "Wemade Entertainment" and
            pe.signatures[i].serial == "61:00:39:d6:34:9e:e5:31:e4:ca:a3:a6:5d:10:0c:7d" and
            1341792000 <= pe.signatures[i].not_after
        )
}