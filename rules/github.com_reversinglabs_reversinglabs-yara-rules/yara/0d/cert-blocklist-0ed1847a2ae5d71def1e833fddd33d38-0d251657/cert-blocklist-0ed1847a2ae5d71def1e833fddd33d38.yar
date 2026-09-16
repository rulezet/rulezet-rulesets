import "pe"
rule cert_blocklist_0ed1847a2ae5d71def1e833fddd33d38 {
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
            pe.signatures[i].subject contains "SNAB-RESURS, OOO" and
            pe.signatures[i].serial == "0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38" and
            1598662800 <= pe.signatures[i].not_after
        )
}